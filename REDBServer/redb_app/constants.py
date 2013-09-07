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


class matching_grade:
    """
    Constants related to the final filtering of the DB.
    """
    MATCHING_THRESHOLD = 0.9

    GRAPH_SIMILARITY_WEIGHT = 0.95
    FRAME_SIMILARITY_WEIGHT = 0.05


class graph_similarity:
    """
    Constants which affect the graph similarity algorithm.
    """
    MAX_GRAPH_COMP_SIZE = 5000
    MIN_CLIQUE_GRAPH_RATIO = 0.3


class block_similarity:
    """
    Constants which affect the block similarity.
    """
    BLOCK_SIMILARITY_THRESHOLD = 0.75

    STR_FLEXIBILITY = 0.85

    MIN_BLOCK_DIST_SIMILARITY = 0.75


class frame_similarity:
    """
    Constants which affect the frame similarity.
    """
    ARGS_SIZE_WEIGHT = 0.4
    VARS_SIZE_WEIGHT = 0.3
    REGS_SIZE_WEIGHT = 0.3
