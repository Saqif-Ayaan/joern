package io.joern.dataflowengineoss.queryengine

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Helpers to recognize effective syntactic sanitizers: conditional checks (e.g. `if (len > MAX) return;`)
  * that actually prevent tainted data from reaching a sink, as opposed to cosmetic checks that do not.
  */
object SyntacticSanitizer {

  /** True if `conditionNode` is the condition of an IF whose "bad" branch (whenTrue for upper-bound
    * checks like `x > LIMIT`) does not reach `sink`, and the condition references a source parameter.
    * In that case the conditional acts as a valid sanitizer and we can treat it as such.
    */
  def isEffectiveConditionalSanitizer(
    conditionNode: Expression,
    sink: CfgNode,
    sourceParamNames: Set[String]
  ): Boolean = {
    if (sourceParamNames.isEmpty) return false

    val ctrlOpt = conditionNode.astParentOption.collect { case c: ControlStructure => c }
    if (ctrlOpt.isEmpty) return false

    val ctrl = ctrlOpt.get
    if (ctrl.controlStructureType != ControlStructureTypes.IF) return false

    if (!conditionReferencesSource(conditionNode, sourceParamNames)) return false

    if (!sameMethod(conditionNode, sink)) return false

    val whenTrueRootOpt = ctrl.astChildren.toList.find(_.order == 2)
    if (whenTrueRootOpt.isEmpty) return false

    val badBranchCfgNodes = whenTrueRootOpt.get.ast.isCfgNode.toList
    !badBranchReachesSink(badBranchCfgNodes, sink)
  }

  /** True if `sink` is protected by at least one effective IF-condition sanitizer for `sourceParamName`
    * in the same method. This check is useful when the data-flow traversal does not explicitly visit the
    * condition expression node.
    */
  def sinkSanitizedByConditionalCheck(sink: CfgNode, sourceParamName: String): Boolean = {
    if (sourceParamName.isEmpty) return false
    sink.method.controlStructure.isIf.exists { ctrl =>
      ctrl.condition.headOption.exists { cond =>
        isEffectiveConditionalSanitizer(cond, sink, Set(sourceParamName))
      }
    }
  }

  private def conditionReferencesSource(conditionNode: Expression, sourceParamNames: Set[String]): Boolean =
    conditionNode.ast.isIdentifier.name.toSet.intersect(sourceParamNames).nonEmpty

  private def sameMethod(conditionNode: Expression, sink: CfgNode): Boolean =
    conditionNode.isInstanceOf[CfgNode] && conditionNode.asInstanceOf[CfgNode].method == sink.method

  private def badBranchReachesSink(badBranchCfgNodes: List[CfgNode], sink: CfgNode): Boolean = {
    val visited = mutable.Set.empty[CfgNode]
    val worklist = mutable.Queue[CfgNode](badBranchCfgNodes*)
    while (worklist.nonEmpty) {
      val n = worklist.dequeue()
      if (n == sink) return true
      if (!visited(n)) {
        visited.add(n)
        n.cfgNext.foreach(worklist.enqueue)
      }
    }
    false
  }
}
