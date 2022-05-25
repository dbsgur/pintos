#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H
#define P 17
#define Q 14
#define FRACTION 1 << (Q)
/* Fixed-point real arithmetic */
/* Here x and y are fixed-point number, n is an integer */
#define CONVERT_TO_FP(n) (n) * (FRACTION)
#define CONVERT_TO_INT_ZERO(x) (x) / (FRACTION)
#define CONVERT_TO_INT_NEAREST(x) ((x) >= 0 ? ((x) + (FRACTION) / 2)\
                                   / (FRACTION) : ((x) - (FRACTION) / 2)\
                                   / (FRACTION))
#define ADD(x, y) (x) + (y)
#define SUB(x, y) (x) - (y)
#define ADD_INT(x, n) (x) + (n) * (FRACTION)
#define SUB_INT(x, n) (x) - (n) * (FRACTION)
#define MULTIPLE(x, y) ((int64_t)(x)) * (y) / (FRACTION)
#define MULT_INT(x, n) (x) * (n)
#define DIVIDE(x, y) ((int64_t)(x)) * (FRACTION) / (y)
#define DIV_INT(x, n) (x) / (n)
#endif

// #define F (1 << 14) //fixed point 1
// #define INT_MAX ((1 << 31) - 1)
// #define INT_MIN (-(1 << 31))
// // x and y denote fixed_point numbers in 17.14 format
// // n is an integer
// int int_to_fp(int n); /* integer를 fixed point로 전환 */
// int fp_to_int_round(int x); /* FP를 int로 전환(반올림) */
// int fp_to_int(int x); /* FP를 int로 전환(버림) */
// int add_fp(int x, int y); /* FP의 덧셈 */
// int add_mixed(int x, int n); /* FP와 int의 덧셈 */
// int sub_fp(int x, int y); /* FP의 뺄셈(x-y) */
// int sub_mixed(int x, int n); /* FP와 int의 뺄셈(x-n) */
// int mult_fp(int x, int y); /* FP의 곱셈 */
// int mult_mixed(int x, int y); /* FP와 int의 곱셈 */
// int div_fp(int x, int y); /* FP의 나눗셈(x/y) */
// int div_mixed(int x, int n); /* FP와 int 나눗셈(x/n) */
