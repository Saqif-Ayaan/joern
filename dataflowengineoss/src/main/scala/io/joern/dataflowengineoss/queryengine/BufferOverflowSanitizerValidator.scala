package io.joern.dataflowengineoss.queryengine

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import scala.collection.mutable

/** Lightweight validator for numeric sanitizer methods used in buffer-overflow workflows.
  *
  * We currently validate common clamp-style implementations and cache the result per method.
  */
object BufferOverflowSanitizerValidator {

  val ValidatorVersion = "clamp-stage3-v1"

  private val cache = mutable.HashMap.empty[String, Boolean]

  private val CastOperator        = "<operator>.cast"
  private val ConditionalOperator = "<operator>.conditional"
  private val AssignmentOperator  = "<operator>.assignment"
  private val ComparatorOperators = Set(
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan"
  )
  private val IfControlStructure = "IF"

  private case class AbstractState(mustBounded: Boolean, upperBounds: Set[String])
  private case class NormalizedComparison(op: String, bound: String)
  private case class IfBranchInfo(
    conditionCallId: Long,
    normalized: NormalizedComparison,
    trueBranchNodeIds: Set[Long],
    falseBranchNodeIds: Set[Long]
  )

  def isValidatedSanitizer(method: Method): Boolean = synchronized {
    cache.getOrElseUpdate(method.fullName, validate(method))
  }

  def validatorVersion: String = ValidatorVersion

  def methodFingerprint(method: Method): String = {
    val cfgCodes = method.start.cfgNode.l
      .sortBy(_.id)
      .map(node => Option(node.code).map(_.trim).getOrElse(""))
      .mkString("\u001f")
    sha256Hex(
      s"${method.fullName}\u001e${Option(method.signature).getOrElse("")}\u001e$cfgCodes"
    )
  }

  def clearCacheForTests(): Unit = synchronized {
    cache.clear()
  }

  private def validate(method: Method): Boolean = {
    val paramNameOpt = method.parameter.sortBy(_.index).headOption.map(_.name).filter(_.nonEmpty)
    if (paramNameOpt.isEmpty) {
      return false
    }
    val paramName = paramNameOpt.get

    val returns = method.ast.isReturn.flatMap(ret => returnExpression(ret).map(expr => (ret, expr))).toList
    if (returns.isEmpty) {
      return false
    }

    validateViaCfg(method, paramName, returns)
  }

  private def returnExpression(ret: Return): Option[Expression] =
    ret.astChildren.collectAll[Expression].headOption

  private def trimmedCode(expr: Expression): Option[String] =
    Option(expr.code).map(_.trim).filter(_.nonEmpty)

  private def isLikelyConstantIdentifier(token: String): Boolean =
    token.matches("[A-Z_][A-Z0-9_]*")

  /** Returns a bound token only for strict constant-like bound expressions.
    *
    * To keep false positives low, we intentionally reject calls/arithmetic/unknown expressions here.
    */
  private def strictBoundToken(expr: Expression, paramName: String): Option[String] = expr match {
    case lit: Literal =>
      trimmedCode(lit)
    case id: Identifier if id.name.nonEmpty && id.name != paramName =>
      val tokenOpt          = trimmedCode(id)
      val isConstantLike    = tokenOpt.exists(isLikelyConstantIdentifier)
      val referencesProgramValue =
        id.refsTo.collectAll[Local].nonEmpty || id.refsTo.collectAll[MethodParameterIn].nonEmpty
      if (isConstantLike && !referencesProgramValue) tokenOpt else None
    case call: Call if call.name == CastOperator =>
      Option(call.argument(2)).collect { case e: Expression => e }.flatMap(arg => strictBoundToken(arg, paramName))
    case call: Call
        if call.argument.isEmpty && isLikelyConstantIdentifier(call.name) && trimmedCode(call).contains(call.name) =>
      // Some frontends emit macro-like constants (e.g., MAX) as zero-arg calls.
      Some(call.name)
    case _ =>
      None
  }

  private def isClampStyleConditional(call: Call, paramName: String): Boolean = {
    val condOpt = Option(call.argument(1)).collect { case c: Call => c }
    val thenOpt = Option(call.argument(2))
    val elseOpt = Option(call.argument(3))

    (condOpt, thenOpt, elseOpt) match {
      case (Some(cond), Some(thenExpr), Some(elseExpr)) =>
        val branch1 = branchMatches(cond, boundedExpr = thenExpr, paramExpr = elseExpr, paramName)
        val branch2 = branchMatches(cond, boundedExpr = elseExpr, paramExpr = thenExpr, paramName)
        branch1 || branch2
      case _ =>
        false
    }
  }

  private def branchMatches(cond: Call, boundedExpr: Expression, paramExpr: Expression, paramName: String): Boolean = {
    if (!isIdentifierNamed(paramExpr, paramName) || !ComparatorOperators.contains(cond.name)) {
      return false
    }
    val boundedTokenOpt = strictBoundToken(boundedExpr, paramName)
    if (boundedTokenOpt.isEmpty) {
      return false
    }
    val boundedToken = boundedTokenOpt.get
    normalizedComparison(cond, paramName).exists(_.bound == boundedToken)
  }

  private def isIdentifierNamed(expr: Expression, name: String): Boolean = expr match {
    case id: Identifier => id.name == name
    case _              => false
  }

  /** CFG-based validator for clamp-like numeric sanitizers.
    *
    * We propagate a MUST-bounded fact for the tracked parameter across CFG edges. A sanitizer is validated iff all
    * returns are proven safe under this abstraction.
    */
  private def validateViaCfg(method: Method, paramName: String, returns: List[(Return, Expression)]): Boolean = {
    val cfgNodes = method.start.cfgNode.l
    if (cfgNodes.isEmpty) {
      return false
    }
    val cfgNodeIds = cfgNodes.map(_.id).toSet

    val ifInfosById = method.start.controlStructure
      .filter(_.controlStructureType == IfControlStructure)
      .flatMap(ifNode => ifBranchInfo(ifNode, paramName).map(info => ifNode.id -> info))
      .toMap
    val ifInfosByConditionCallId = ifInfosById.values.map(info => info.conditionCallId -> info).toMap

    // `method.start.cfgNode` can omit some predecessor nodes (e.g., parameters), so
    // treat nodes whose predecessors are outside this slice as graph roots as well.
    val entryNodes = cfgNodes.filter { node =>
      val prevIds = node.cfgPrev.id.l
      prevIds.isEmpty || prevIds.forall(prevId => !cfgNodeIds.contains(prevId))
    }
    if (entryNodes.isEmpty) {
      return false
    }

    val inStates  = mutable.HashMap.empty[Long, AbstractState]
    val workQueue = mutable.Queue.empty[CfgNode]

    entryNodes.foreach { entry =>
      inStates.update(entry.id, AbstractState(mustBounded = false, upperBounds = Set.empty))
      workQueue.enqueue(entry)
    }

    while (workQueue.nonEmpty) {
      val current          = workQueue.dequeue()
      val currentInState   = inStates.getOrElse(current.id, AbstractState(mustBounded = false, upperBounds = Set.empty))
      val currentOutState  = refinedStateAtNode(current, currentInState, paramName)
      val successors   = current.cfgNext.l

      successors.foreach { succ =>
        val edgeState = refinedStateForEdge(current, succ, currentOutState, ifInfosById, ifInfosByConditionCallId)
        val updated = inStates.get(succ.id) match {
          case Some(existing) =>
            val merged = mergeMustState(existing, edgeState)
            if (merged != existing) {
              inStates.update(succ.id, merged)
              true
            } else {
              false
            }
          case None =>
            inStates.update(succ.id, edgeState)
            true
        }
        if (updated) {
          workQueue.enqueue(succ)
        }
      }
    }

    returns.forall { case (ret, expr) =>
      val stateAtReturn = inStates.getOrElse(ret.id, AbstractState(mustBounded = false, upperBounds = Set.empty))
      isSafeReturnGivenState(ret, expr, paramName, stateAtReturn, ifInfosByConditionCallId)
    }
  }

  private def refinedStateForEdge(
    current: CfgNode,
    successor: CfgNode,
    state: AbstractState,
    ifInfosById: Map[Long, IfBranchInfo],
    ifInfosByConditionCallId: Map[Long, IfBranchInfo]
  ): AbstractState = {
    current match {
      case ifNode: ControlStructure =>
        ifInfosById.get(ifNode.id).map(info => refineStateForIfBranch(successor, state, info)).getOrElse(state)
      case condCall: Call =>
        ifInfosByConditionCallId
          .get(condCall.id)
          .map(info => refineStateForIfBranch(successor, state, info))
          .getOrElse(state)
      case _ =>
        state
    }
  }

  private def refineStateForIfBranch(successor: CfgNode, state: AbstractState, info: IfBranchInfo): AbstractState = {
    if (info.trueBranchNodeIds.contains(successor.id)) {
      applyComparisonOnBranch(state, info.normalized, isTrueBranch = true)
    } else if (info.falseBranchNodeIds.contains(successor.id) || !info.trueBranchNodeIds.contains(successor.id)) {
      // For `if` without an explicit `else`, CFG false-branch successors are often outside `whenFalse`.
      applyComparisonOnBranch(state, info.normalized, isTrueBranch = false)
    } else {
      state
    }
  }

  private def refinedStateAtNode(current: CfgNode, state: AbstractState, paramName: String): AbstractState = {
    current match {
      case call: Call if call.name == AssignmentOperator =>
        refineStateForAssignment(call, state, paramName)
      case _ =>
        state
    }
  }

  private def refineStateForAssignment(call: Call, state: AbstractState, paramName: String): AbstractState = {
    val lhsOpt = Option(call.argument(1))
    val rhsOpt = Option(call.argument(2)).collect { case expr: Expression => expr }
    (lhsOpt, rhsOpt) match {
      case (Some(lhs: Expression), Some(rhs)) if isIdentifierNamed(lhs, paramName) =>
        rhs match {
          case id: Identifier if id.name == paramName =>
            // Identity assignment preserves current facts.
            state
          case _ =>
            strictBoundToken(rhs, paramName) match {
              case Some(bound) =>
                // Strong update: parameter is overwritten by a strict bound.
                state.copy(mustBounded = true, upperBounds = Set(bound))
              case _ =>
                // Unknown overwrite of the tracked parameter: kill existing upper-bound facts.
                state.copy(mustBounded = false, upperBounds = Set.empty)
            }
        }
      case _ =>
        state
    }
  }

  private def mergeMustState(a: AbstractState, b: AbstractState): AbstractState = {
    val must = a.mustBounded && b.mustBounded
    AbstractState(must, if (must) a.upperBounds.intersect(b.upperBounds) else Set.empty)
  }

  private def isSafeReturnGivenState(
    ret: Return,
    expr: Expression,
    paramName: String,
    state: AbstractState,
    ifInfosByConditionCallId: Map[Long, IfBranchInfo]
  ): Boolean = expr match {
    case _: Literal                                    => true
    case call: Call if call.name == ConditionalOperator => isClampStyleConditional(call, paramName)
    case _ if strictBoundToken(expr, paramName).nonEmpty => true
    case id: Identifier if id.name == paramName =>
      state.mustBounded || isUpperBoundGuardedReturn(ret, ifInfosByConditionCallId)
    case _                                             => false
  }

  private def isUpperBoundGuardedReturn(
    ret: Return,
    ifInfosByConditionCallId: Map[Long, IfBranchInfo]
  ): Boolean = {
    ret.start.controlledBy
      .collectAll[Call]
      .exists { condCall =>
        ifInfosByConditionCallId.get(condCall.id).exists { info =>
          val inTrueBranch          = info.trueBranchNodeIds.contains(ret.id)
          val inFalseBranchExplicit = info.falseBranchNodeIds.contains(ret.id)
          val inFalseBranchImplicit = !inTrueBranch && info.falseBranchNodeIds.isEmpty
          branchImpliesUpperBound(info.normalized.op, inTrueBranch || inFalseBranchExplicit || inFalseBranchImplicit, inTrueBranch)
        }
      }
  }

  private def branchImpliesUpperBound(normalizedOp: String, isKnownBranch: Boolean, isTrueBranch: Boolean): Boolean = {
    if (!isKnownBranch) {
      false
    } else {
      normalizedOp match {
        case "<operator>.lessThan" | "<operator>.lessEqualsThan"      => isTrueBranch
        case "<operator>.greaterThan" | "<operator>.greaterEqualsThan" => !isTrueBranch
        case _                                                        => false
      }
    }
  }

  private def ifBranchInfo(ifNode: ControlStructure, paramName: String): Option[IfBranchInfo] = {
    val condOpt = ifNode.start.condition.headOption.collect { case c: Call => c }
    condOpt.flatMap(cond =>
      normalizedComparison(cond, paramName).map { normalized =>
        val trueIds  = ifNode.start.whenTrue.ast.isCfgNode.id.l.toSet
        val falseIds = ifNode.start.whenFalse.ast.isCfgNode.id.l.toSet
        IfBranchInfo(cond.id, normalized, trueIds, falseIds)
      }
    )
  }

  private def normalizedComparison(cond: Call, paramName: String): Option[NormalizedComparison] = {
    if (!ComparatorOperators.contains(cond.name)) {
      return None
    }
    val lhs = Option(cond.argument(1))
    val rhs = Option(cond.argument(2))
    (lhs, rhs) match {
      case (Some(l: Expression), Some(r: Expression)) if isIdentifierNamed(l, paramName) =>
        strictBoundToken(r, paramName).map(bound => NormalizedComparison(normalizedOperator(cond.name, paramOnLhs = true), bound))
      case (Some(l: Expression), Some(r: Expression)) if isIdentifierNamed(r, paramName) =>
        strictBoundToken(l, paramName).map(bound => NormalizedComparison(normalizedOperator(cond.name, paramOnLhs = false), bound))
      case _ =>
        None
    }
  }

  private def normalizedOperator(op: String, paramOnLhs: Boolean): String = {
    if (paramOnLhs) {
      op
    } else {
      op match {
        case "<operator>.greaterThan"       => "<operator>.lessThan"
        case "<operator>.greaterEqualsThan" => "<operator>.lessEqualsThan"
        case "<operator>.lessThan"          => "<operator>.greaterThan"
        case "<operator>.lessEqualsThan"    => "<operator>.greaterEqualsThan"
        case other                          => other
      }
    }
  }

  private def applyComparisonOnBranch(
    state: AbstractState,
    comparison: NormalizedComparison,
    isTrueBranch: Boolean
  ): AbstractState = {
    val impliesUpperBound = comparison.op match {
      case "<operator>.lessThan" | "<operator>.lessEqualsThan"   => isTrueBranch
      case "<operator>.greaterThan" | "<operator>.greaterEqualsThan" => !isTrueBranch
      case _                                                     => false
    }
    if (impliesUpperBound) {
      state.copy(mustBounded = true, upperBounds = state.upperBounds + comparison.bound)
    } else {
      state
    }
  }

  private def sha256Hex(input: String): String = {
    val digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8))
    digest.map(byte => f"${byte & 0xff}%02x").mkString
  }
}
