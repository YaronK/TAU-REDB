class db_filter:
    """
    Constants related to the preliminary filtering of the DB.
    """
    MAX_NUM_INSNS_DEVIATION = 0.2
    MAX_NUM_BLOCKS_DEVIATION = 0.2
    MAX_NUM_EDGES_DEVIATION = 0.2
    MAX_NUM_STRINGS_DEVIATION = 0.2
    MAX_NUM_CALLS_DEVIATION = 0.2
    MAX_VARS_SIZE_DEVIATION = 0.3
    MAX_ARGS_SIZE_DEVIATION = 0.3
    MAX_REGS_SIZE_DEVIATION = 0.3
    MAX_NUM_IMMS_DEVIATION = 0.2


class dict_filter:
    """
    Constants related to the secondary filtering of the DB.
    """
    ITYPES_THRESHOLD = 0.8


class matching_grade_filter:
    """
    Constants related to the final filtering of the DB.
    """
    MATCHING_THRESHOLD = 0.9

REQUIRED_ATTRIBUTES = ["func_signature",
                       "func_name",
                       "frame_attributes",
                       "itypes",
                       "strings",
                       "immediates",
                       "calls",
                       "exe_signature",
                       "exe_name",
                       "graph"]
