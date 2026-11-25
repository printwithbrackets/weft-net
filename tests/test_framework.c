/* test_framework.c - regression tests for the harness itself.
 *
 * A skipped test must be reported as skipped, never as OK and never as a
 * failure. The counts are file-static globals shared by every test in the
 * binary, so the second test below can read the first one's outcome and
 * assert on it directly. */
#include "test_framework.h"

/* Deliberately skip: proves SKIP_TEST reports SKIP, not OK. */
TEST(test_skip_outcome_is_reported_as_skip) {
    SKIP_TEST("intentional skip for the harness regression test");
}

/* Runs after the skip above: the totals must show one run, zero failures,
 * one skipped. A skipped test must not count as passed. */
TEST(test_skip_does_not_count_as_passed) {
    ASSERT_EQ(wn_tests_run, 2);
    ASSERT_EQ(wn_tests_failed, 0);
    ASSERT_EQ(wn_tests_skipped, 1);
}

int main(void) {
    printf("framework tests\n");
    RUN_TEST(test_skip_outcome_is_reported_as_skip);
    RUN_TEST(test_skip_does_not_count_as_passed);
    TEST_SUMMARY();
}