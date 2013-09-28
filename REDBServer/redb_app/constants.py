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
    MAX_NUM_INSNS_DEVIATION = 0.95
    MAX_NUM_EDGES_DEVIATION = 0.2
    MAX_NUM_BLOCKS_DEVIATION = 0.2
    MAX_NUM_STRINGS_DEVIATION = 0.2
    MAX_NUM_CALLS_DEVIATION = 0.2
    MAX_NUM_IMMS_DEVIATION = 0.2
    MAX_VARS_SIZE_DEVIATION = 0.6
    MAX_ARGS_SIZE_DEVIATION = 0.6
    MAX_REGS_SIZE_DEVIATION = 0.6

    COARSE_FILTER_FIRST_RANGE = 10
    COARSE_FILTER_SECOND_RANGE = 15
    COARSE_FILTER_THIRD_RANGE = 20
    COARSE_FILTER_FOURTH_RANGE = 60
    COARSE_FILTER_FIFTH_RANGE = 100
    COARSE_FILTER_SIXTH_RANGE = 200

    COARSE_FILTER_ZERO_RANGE_DEV = 6
    COARSE_FILTER_FIRST_RANGE_DEV = 2
    COARSE_FILTER_SECOND_RANGE_DEV = 2
    COARSE_FILTER_THIRD_RANGE_DEV = 1.5
    COARSE_FILTER_FOURTH_RANGE_DEV = 0.5
    COARSE_FILTER_FIFTH_RANGE_DEV = 0.4
    COARSE_FILTER_SIXTH_RANGE_DEV = 0.3
    COARSE_FILTER_SEVENTH_RANGE_DEV = 0.2

    FINE_FILTER_ZERO_RANGE_DEV = 4

class dict_filter:
    """
    Constants related to the secondary filtering of the DB.
    """
    ITYPES_THRESHOLD = 0.8


class matching_grade:
    """
    Constants related to the final filtering of the DB.
    """
    MATCHING_THRESHOLD = 0.65

    GRAPH_SIMILARITY_WEIGHT = 0.95
    # TODO: maybe give frame similarity more weight?
    FRAME_SIMILARITY_WEIGHT = 0.05


class graph_similarity:
    """
    Constants which affect the graph similarity algorithm.
    """
    ASSOCIATION_GRAPH_MAX_SIZE = 5000
    GRAPH_PRODUCT_MAX_SIZE = 10000


class block_similarity:
    """
    Constants which affect the block similarity.
    """
    STRING_VALUE_FLEXIBILITY = 0.6
    CALL_NAME_FLEXIBILITY = 0.6

    BLOCK_SIMILARITY_THRESHOLD = 0.2
    MIN_BLOCK_DIST_SIMILARITY = 0.7


class frame_similarity:
    """
    Constants which affect the frame similarity.
    """
    ARGS_SIZE_WEIGHT = 0.4
    VARS_SIZE_WEIGHT = 0.3
    REGS_SIZE_WEIGHT = 0.3
