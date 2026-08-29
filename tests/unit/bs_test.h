/* Minimal TAP harness for the unit tests.
 *
 * TAP because it is trivially machine-readable, needs no dependency, and
 * every CI system already understands it. The whole harness is forty lines,
 * which is the point: a test framework that needs its own tests is a liability
 * in a project whose entire claim is that it has no dependencies.
 */

#ifndef BS_TEST_H_INCLUDED
#define BS_TEST_H_INCLUDED

#include <stdio.h>

static int bs_test_n = 0;
static int bs_test_bad = 0;

static void bs_test_report(int ok, const char *expr, const char *file,
                           int line) {
  bs_test_n++;
  if (ok) {
    (void)printf("ok %d - %s\n", bs_test_n, expr);
  } else {
    bs_test_bad++;
    (void)printf("not ok %d - %s\n", bs_test_n, expr);
    (void)printf("# failed at %s:%d\n", file, line);
  }
}

#define CHECK(expr) bs_test_report((expr) ? 1 : 0, #expr, __FILE__, __LINE__)

static int bs_test_finish(void) {
  (void)printf("1..%d\n", bs_test_n);
  return (bs_test_bad == 0) ? 0 : 1;
}

#endif /* BS_TEST_H_INCLUDED */
