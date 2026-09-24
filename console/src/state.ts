import { ResourceState } from "./gen/dariya/common/v1/common_pb";

/** Renders the lifecycle enum for a person.
 *
 *  Mapped exhaustively rather than by stripping a prefix off the name: a switch with no default
 *  makes adding a state to the proto a compile error here, which is the console earning its
 *  place as the contract's second consumer rather than silently showing a number. */
export function stateLabel(state: ResourceState): string {
  switch (state) {
    case ResourceState.ACTIVE:
      return "active";
    case ResourceState.CREATING:
      return "creating";
    case ResourceState.UPDATING:
      return "updating";
    case ResourceState.DELETING:
      return "deleting";
    case ResourceState.FAILED:
      return "failed";
    case ResourceState.UNSPECIFIED:
      return "unknown";
  }
}
