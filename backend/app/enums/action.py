from enum import Enum


class Action(str, Enum):
    BLOCK = "Block"
    BLOCK_AND_REMEDIATE = "BlockAndRemediate"
