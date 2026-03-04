package io.joern.dataflowengineoss.queryengine

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Lightweight validator for numeric sanitizer methods used in buffer-overflow workflows.
  *
  * We currently validate common clamp-style implementations and cache the result per method.
  */
object BufferOverflowSanitizerValidator {

  private val cache = mutable.HashMap.empty[String, Boolean]

  private val ConditionalOperator = "<operator>.conditional"
  private val AssignmentOperator  = "<operator>.assignment"
  private val ComparatorOperators = Set(
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan"
  )
  private val IfControlStructure = "IF"

  private case class AbstractState(upperBounds: Set[String])
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

    val allBoundedSyntactically = returns.forall { case (_, expr) => isBoundedReturn(expr, paramName) }
    val assignmentLadder        = isAssignmentClampLadder(method, paramName, returns)
    val cfgValidated            = if (!allBoundedSyntactically && !assignmentLadder) validateViaCfg(method, paramName, returns) else false
    allBoundedSyntactically || assignmentLadder || cfgValidated
  }

  private def returnExpression(ret: Return): Option[Expression] =
    ret.astChildren.collectAll[Expression].headOption

  private def isBoundedReturn(expr: Expression, paramName: String): Boolean = expr match {
    case _: Literal                                    => true
    case call: Call if call.name == ConditionalOperator => isClampStyleConditional(call, paramName)
    case _ if boundCode(expr).nonEmpty && !isIdentifierNamed(expr, paramName) => true
    case id: Identifier if id.name == paramName        => false
    case _                                             => false
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
    val boundedCodeOpt = boundCode(boundedExpr)
    if (boundedCodeOpt.isEmpty) {
      return false
    }
    val boundedCode = boundedCodeOpt.get

    val lhs = Option(cond.argument(1))
    val rhs = Option(cond.argument(2))
    (lhs, rhs) match {
      case (Some(l), Some(r)) =>
        (isIdentifierNamed(l, paramName) && expressionCode(r).contains(boundedCode)) ||
        (isIdentifierNamed(r, paramName) && expressionCode(l).contains(boundedCode))
      case _ =>
        false
    }
  }

  private def isIdentifierNamed(expr: Expression, name: String): Boolean = expr match {
    case id: Identifier => id.name == name
    case _              => false
  }

  private def boundCode(expr: Expression): Option[String] = expr match {
    case lit: Literal                        => Option(lit.code).filter(_.nonEmpty)
    case id: Identifier if id.name.nonEmpty => Option(id.code).filter(_.nonEmpty)
    case call: Call                          => Option(call.code).filter(_.nonEmpty)
    case _                                   => None
  }

  private def expressionCode(expr: Expression): Option[String] =
    Option(expr.code).filter(_.nonEmpty)

  private def isAssignmentClampLadder(method: Method, paramName: String, returns: List[(Return, Expression)]): Boolean = {
    val hasParamReturn = returns.exists { case (_, expr) =>
      expr match {
        case id: Identifier => id.name == paramName
        case _              => false
      }
    }
    if (!hasParamReturn) {
      return false
    }

    val ifNodes = method.start.controlStructure.filter(_.controlStructureType == IfControlStructure).l
    if (ifNodes.isEmpty) {
      return false
    }

    val condBounds = ifNodes.flatMap { ifNode =>
      ifNode.start.condition.headOption.collect { case c: Call => c }.flatMap { cond =>
        if (ComparatorOperators.contains(cond.name)) {
          Option(cond.argument(2)).flatMap(arg => Option(arg.code).map(_.trim).filter(_.nonEmpty))
        } else {
          None
        }
      }
    }.toSet
    if (condBounds.isEmpty) {
      return false
    }

    val assignmentBounds = method.ast.isCall
      .name(AssignmentOperator)
      .flatMap(assignCall => assignmentBoundForParam(assignCall, paramName))
      .toSet

    condBounds.subsetOf(assignmentBounds)
  }

  private def assignmentBoundForParam(assignCall: Call, paramName: String): Option[String] = {
    val lhsOpt = Option(assignCall.argument(1)).collect { case e: Expression => e }
    val rhsOpt = Option(assignCall.argument(2)).collect { case e: Expression => e }
    (lhsOpt, rhsOpt) match {
      case (Some(lhs), Some(rhs)) if isIdentifierNamed(lhs, paramName) =>
        boundCode(rhs).map(_.trim).filter(_.nonEmpty)
      case _ =>
        None
    }
  }

  private def isParamAssignedToBound(assignCall: Call, paramName: String, bound: String): Boolean = {
    assignmentBoundForParam(assignCall, paramName).contains(bound)
  }

  /** CFG-based fallback validator for non-ternary sanitizer implementations.
    *
    * We propagate MUST upper-bound constraints (e.g., n <= MAX) across CFG edges. For returns that directly return the
    * parameter, we require at least one guaranteed upper bound on all reaching paths.
    */
  private def validateViaCfg(method: Method, paramName: String, returns: List[(Return, Expression)]): Boolean = {
    val cfgNodes = method.start.cfgNode.l
    if (cfgNodes.isEmpty) {
      return false
    }

    val ifInfosById = method.start.controlStructure
      .filter(_.controlStructureType == IfControlStructure)
      .flatMap(ifNode => ifBranchInfo(ifNode, paramName).map(info => ifNode.id -> info))
      .toMap
    val ifInfosByConditionCallId = ifInfosById.values.map(info => info.conditionCallId -> info).toMap

    val entryNodes = cfgNodes.filter(_.cfgPrev.isEmpty)
    if (entryNodes.isEmpty) {
      return false
    }

    val inStates  = mutable.HashMap.empty[Long, AbstractState]
    val workQueue = mutable.Queue.empty[CfgNode]

    entryNodes.foreach { entry =>
      inStates.update(entry.id, AbstractState(Set.empty))
      workQueue.enqueue(entry)
    }

    while (workQueue.nonEmpty) {
      val current          = workQueue.dequeue()
      val currentInState   = inStates.getOrElse(current.id, AbstractState(Set.empty))
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
      val stateAtReturn = inStates.getOrElse(ret.id, AbstractState(Set.empty))
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
            // Identity assignment preserves current upper-bound facts.
            state
          case _ =>
            boundCode(rhs) match {
              case Some(bound) if !isIdentifierNamed(rhs, paramName) =>
                // Strong update: parameter is overwritten by a bounded expression.
                state.copy(upperBounds = Set(bound))
              case _ =>
                // Unknown overwrite of the tracked parameter: kill existing upper-bound facts.
                state.copy(upperBounds = Set.empty)
            }
        }
      case _ =>
        state
    }
  }

  private def mergeMustState(a: AbstractState, b: AbstractState): AbstractState =
    AbstractState(a.upperBounds.intersect(b.upperBounds))

  private def isSafeReturnGivenState(
    ret: Return,
    expr: Expression,
    paramName: String,
    state: AbstractState,
    ifInfosByConditionCallId: Map[Long, IfBranchInfo]
  ): Boolean = expr match {
    case _: Literal                                    => true
    case call: Call if call.name == ConditionalOperator => isClampStyleConditional(call, paramName)
    case _ if boundCode(expr).nonEmpty && !isIdentifierNamed(expr, paramName) => true
    case id: Identifier if id.name == paramName =>
      state.upperBounds.nonEmpty || isUpperBoundGuardedReturn(ret, ifInfosByConditionCallId)
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
        boundCode(r).map(bound => NormalizedComparison(normalizedOperator(cond.name, paramOnLhs = true), bound))
      case (Some(l: Expression), Some(r: Expression)) if isIdentifierNamed(r, paramName) =>
        boundCode(l).map(bound => NormalizedComparison(normalizedOperator(cond.name, paramOnLhs = false), bound))
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
      state.copy(upperBounds = state.upperBounds + comparison.bound)
    } else {
      state
    }
  }
}

