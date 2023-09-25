from unittest import TestCase, main
from unittest.mock import MagicMock
from ufw import filter_tools


class FilterFunctionTests(TestCase):
    """
    Tests for ensuring the FilterFunction class is capable of wrapping a
    function and combining with other FilterFunctions to create complex
    logical combinations
    """
    def test_executes_provided_function_on_value(self):
        """Tests that FilterFunction objects will execute the function provided
        to them when they are called like functions"""
        filter_func = filter_tools.FilterFunction(lambda val: val + 5)
        self.assertEqual(filter_func(5), 10)

    def test_can_combine_two_booleans_with_ampersand_operator(self):
        """Tests that when a FilterFunction has the "&" operator used between
        it and another boolean statement, both functions will be executed and
        the "and" result of both will be returned"""
        # function will evaluate if a provided value is GREATER THAN OR EQUALS 5
        filter_func5 = filter_tools.FilterFunction(lambda val: val >= 5)
        # function will evaluate if a provided value is LESS THAN 10
        filter_func10 = filter_tools.FilterFunction(lambda val: val < 10)

        # combination function will evaluate if a value is greater than 5 and
        # less than 10
        combo_func = filter_func5 & filter_func10

        # accepted range: [5, 7)
        self.assertFalse(combo_func(3))
        self.assertTrue(combo_func(5))
        self.assertTrue(combo_func(7))
        self.assertFalse(combo_func(10))
        self.assertFalse(combo_func(12))

    def test_can_combine_two_booleans_with_or_operator(self):
        """Tests that when a FilterFunction has the "|" operator used between
        it and antoher boolean statement, both functions will be executed
        and the "or" result of both will be returned"""
        # function will evaluate if a provided value is LESS THAN OR EQUAL TO 5
        filter_func5 = filter_tools.FilterFunction(lambda val: val <= 5)
        # function will evaluate if a provided value is GREATER than 10
        filter_func10 = filter_tools.FilterFunction(lambda val: val > 10)

        # combination function will evaluate if a value is greater than 5 and
        # less than 10
        combo_func = filter_func5 | filter_func10

        # accepted range: (-inf, 5](10, inf)
        self.assertTrue(combo_func(3))
        self.assertTrue(combo_func(5))
        self.assertFalse(combo_func(7))
        self.assertFalse(combo_func(10))
        self.assertTrue(combo_func(12))


class LogFilterTests(TestCase):

    # The "==", ">=", "<=", ">", and "<" should return functions that
    # evaluate whether any value passed in matches the initial value
    # provided (e.g. str_filter == 'string' should evaluate any provided
    # value to see if it is also equal to 'string')
    #
    # The end goal is to be able to do something like:
    #   relevant_logs = UFWLogfile(<filename>)[DPT == 25565]
    # and receive all log entries where that port was accessed

    def test_instances_cannot_be_changed(self):
        """Tests that LogFilter instances cannot have their attributes changed
        once created"""
        test_filter = filter_tools.LogFilter('sample_value')
        self.assertEqual(test_filter.attr, 'sample_value')

        with self.assertRaises(AttributeError):
            test_filter.attr = 'new_value'

        self.assertEqual(test_filter.attr, 'sample_value')

    def test_equivalency_operator(self):
        """Tests that LogFilter instances return a function when == is
        used and that the function checks provided objects such that
        object.attr == filter-value"""
        str_filter = filter_tools.LogFilter('attr')

        equal_object = MagicMock(attr='string')
        unequal_object = MagicMock(attr='not string')

        filter_function = str_filter == 'string'

        self.assertTrue(filter_function(equal_object))
        self.assertFalse(filter_function(unequal_object))

    def test_non_equivalency_operator(self):
        """Tests that LogFilter instances return a function when == is
        used and that the function checks provided objects such that
        object.attr == filter-value"""
        str_filter = filter_tools.LogFilter('attr')

        equal_object = MagicMock(attr='string')
        unequal_object = MagicMock(attr='not string')

        # The "==", ">=", "<=", ">", and "<" should return functions that
        # evaluate whether any value passed in matches the initial value
        # provided (e.g. str_filter == 'string' should evaluate any provided
        # value to see if it is also equal to 'string')
        filter_function = str_filter != 'string'

        self.assertTrue(filter_function(unequal_object))
        self.assertFalse(filter_function(equal_object))

    def test_greater_than_operator(self):
        """Tests that LogFilter instances return a function when > is
        used and that the function checks provided objects such that
        object.attr > filter-value"""
        int_filter = filter_tools.LogFilter('attr')

        smaller_object = MagicMock(attr=5)
        larger_object = MagicMock(attr=10)

        # 5 < 7 < 10
        filter_function = int_filter > 7

        self.assertTrue(filter_function(smaller_object))
        self.assertFalse(filter_function(larger_object))

    def test_less_than_operator(self):
        """Tests that LogFilter instances return a function when < is
        used and that the function checks provided objects such that
        object.attr < filter-value"""
        int_filter = filter_tools.LogFilter('attr')

        correct_object = MagicMock(attr=10)
        incorrect_object = MagicMock(attr=5)

        # 5 < 7 < 10
        filter_function = int_filter < 7

        self.assertTrue(filter_function(correct_object))
        self.assertFalse(filter_function(incorrect_object))

    def test_greater_than_equal_to_operator(self):
        """Tests that LogFilter instances return a function when >= is
        used and that the function checks provided objects such that
        object.attr >= filter-value"""
        int_filter = filter_tools.LogFilter('attr')

        smaller_object = MagicMock(attr=5)
        equal_object = MagicMock(attr=7)
        larger_object = MagicMock(attr=10)

        # 5 < 7 = 7 < 10
        filter_function = int_filter >= 7

        self.assertTrue(filter_function(smaller_object))
        self.assertTrue(filter_function(equal_object))
        self.assertFalse(filter_function(larger_object))

    def test_less_than_equal_to_operator(self):
        """Tests that LogFilter instances return a function when <= is
        used and that the function checks provided objects such that
        object.attr <= filter-value"""
        int_filter = filter_tools.LogFilter('attr')

        smaller_object = MagicMock(attr=5)
        equal_object = MagicMock(attr=7)
        larger_object = MagicMock(attr=10)

        # 5 < 7 = 7 < 10
        filter_function = int_filter <= 7

        self.assertTrue(filter_function(larger_object))
        self.assertTrue(filter_function(equal_object))
        self.assertFalse(filter_function(smaller_object))

    def test_combine_filters_with_ampersand(self):
        """Tests that a log filter's return functions can be combined with an
        ampersand operator to create a function that returns the "and" value
        of both"""
        int_filter = filter_tools.LogFilter('attr')

        smaller_object = MagicMock(attr=5)
        equal_object = MagicMock(attr=7)
        larger_object = MagicMock(attr=10)

        # 5 < 7 < 10
        filter_function = (int_filter < 5) & (int_filter > 10)

        self.assertFalse(filter_function(larger_object))
        self.assertTrue(filter_function(equal_object))
        self.assertFalse(filter_function(smaller_object))

    def test_combine_filters_with_pipe(self):
        """Tests that a log filter's return functions can be combined with a
        pipe operator to create a function that returns the "or" value
        of both"""
        int_filter = filter_tools.LogFilter('attr')

        smaller_object = MagicMock(attr=5)
        equal_object = MagicMock(attr=7)
        larger_object = MagicMock(attr=10)

        # 5 < 6, 9 < 10
        filter_function = (int_filter > 6) | (int_filter < 9)

        self.assertTrue(filter_function(larger_object))
        self.assertFalse(filter_function(equal_object))
        self.assertTrue(filter_function(smaller_object))


class PresetFiltersTests(TestCase):
    def test_all_filters_are_correct_type(self):
        filters = [filter_tools.EVENT_DATETIME, filter_tools.HOSTNAME,
                   filter_tools.UPTIME, filter_tools.EVENT, filter_tools.IN,
                   filter_tools.OUT, filter_tools.MAC, filter_tools.SRC,
                   filter_tools.DST, filter_tools.LEN, filter_tools.TC,
                   filter_tools.TOS, filter_tools.PERC, filter_tools.TTL,
                   filter_tools.ID, filter_tools.PROTO, filter_tools.SPT,
                   filter_tools.DPT, filter_tools.WINDOW, filter_tools.RES,
                   filter_tools.SYN_URGP, filter_tools.ACK, filter_tools.PSH]
        for log_filter in filters:
            self.assertIsInstance(log_filter, filter_tools.LogFilter)

    def test_filters_have_correct_attribute(self):
        self.assertEqual(filter_tools.EVENT_DATETIME.attr,
                         "event_datetime")
        self.assertEqual(filter_tools.HOSTNAME.attr, "hostname")
        self.assertEqual(filter_tools.UPTIME.attr, "uptime")
        self.assertEqual(filter_tools.EVENT.attr, "event")
        self.assertEqual(filter_tools.IN.attr, "IN")
        self.assertEqual(filter_tools.OUT.attr, "OUT")
        self.assertEqual(filter_tools.MAC.attr, "MAC")
        self.assertEqual(filter_tools.SRC.attr, "SRC")
        self.assertEqual(filter_tools.DST.attr, "DST")
        self.assertEqual(filter_tools.LEN.attr, "LEN")
        self.assertEqual(filter_tools.TC.attr, "TC")
        self.assertEqual(filter_tools.TOS.attr, "TOS")
        self.assertEqual(filter_tools.PERC.attr, "PERC")
        self.assertEqual(filter_tools.TTL.attr, "TTL")
        self.assertEqual(filter_tools.ID.attr, "ID")
        self.assertEqual(filter_tools.PROTO.attr, "PROTO")
        self.assertEqual(filter_tools.SPT.attr, "SPT")
        self.assertEqual(filter_tools.DPT.attr, "DPT")
        self.assertEqual(filter_tools.WINDOW.attr, "WINDOW")
        self.assertEqual(filter_tools.RES.attr, "RES")
        self.assertEqual(filter_tools.SYN_URGP.attr, "SYN_URGP")
        self.assertEqual(filter_tools.ACK.attr, "ACK")
        self.assertEqual(filter_tools.PSH.attr, "PSH")


if __name__ == '__main__':
    main()
