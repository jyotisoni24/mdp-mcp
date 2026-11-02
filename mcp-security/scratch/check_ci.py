from scipy.stats import binomtest

ci_0_53 = binomtest(0, 53).proportion_ci(confidence_level=0.95, method="exact")
ci_0_27 = binomtest(0, 27).proportion_ci(confidence_level=0.95, method="exact")
ci_471_471 = binomtest(471, 471).proportion_ci(confidence_level=0.95, method="exact")

print("0/53 exact CI:", ci_0_53.low, ci_0_53.high)
print("0/27 exact CI:", ci_0_27.low, ci_0_27.high)
print("471/471 exact CI:", ci_471_471.low, ci_471_471.high)
