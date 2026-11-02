# False-Positive Error Analysis: Experimental MCP Detector (Fold 5 Investigation)

## 1. Executive Summary

During the 5-fold server-disjoint cross-validation of the experimental detector model (`LogisticRegression` + TF-IDF word/char n-grams on `data/combined_experimental_dataset.csv`), **Fold 5** evaluated the held-out server family **`filesystem`** (5 benign tools).

At the default decision threshold ($\tau = 0.50$):
* **3 out of 5 benign tools were misclassified as Malicious (False Positives)**:
  * `read_text_file` ($\hat{p} = 0.5781$)
  * `list_directory` ($\hat{p} = 0.5238$)
  * `directory_tree` ($\hat{p} = 0.5892$)
* **2 tools were correctly classified as Benign (True Negatives)**:
  * `write_file` ($\hat{p} = 0.4996$, narrowly under 0.50)
  * `search_files` ($\hat{p} = 0.4006$)

Across the entire 5-fold out-of-fold evaluation (513 total samples: 485 malicious, 28 benign):
* Default threshold ($\tau = 0.50$): False Positive Rate is **39.29%** (11/28 benign misclassified), while False Negative Rate is **0.00%** (0/485 attacks missed, 100% recall).
* Crucially, all three Fold 5 false positives cluster tightly in the narrow probability band **$[0.52, 0.59]$**, indicating marginal confidence driven by generic structural tokens rather than malicious intent tokens.

---

## 2. Detailed False-Positive Tool Profiles

### Tool 1: `read_text_file`

| Field | Value |
|---|---|
| **Server Family** | `filesystem` (Model Context Protocol Official) |
| **Tool Name** | `read_text_file` |
| **Actual Label** | `0` (Benign) |
| **Predicted Label ($\tau = 0.50$)** | `1` (Malicious) |
| **Predicted Malicious Probability ($\hat{p}$)** | **0.5781** (Medium Risk) |
| **Prediction Margin** | $+0.0781$ above decision threshold |

#### Full Description Text
> *"Read the complete contents of a file from the file system as text. Handles various text encodings and provides detailed error messages if the file cannot be read. Use this tool when you need to examine the contents of a single file."*

#### Feature Contribution Analysis ($c_i = x_i \cdot w_i$)

##### Top 10 Features Pushing Towards MALICIOUS (Positive Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__use` | Unigram | 0.164 | +0.220 | +0.0362 |
| `word__tool` | Unigram | 0.077 | +0.429 | +0.0331 |
| `word__this` | Unigram | 0.054 | +0.603 | +0.0325 |
| `word__system` | Unigram | 0.089 | +0.358 | +0.0318 |
| `word__to` | Unigram | 0.041 | +0.692 | +0.0281 |
| `word__you` | Unigram | 0.047 | +0.581 | +0.0272 |
| `word__as` | Unigram | 0.126 | +0.194 | +0.0244 |
| `word__text` | Unigram | 0.286 | +0.076 | +0.0218 |
| `word__when` | Unigram | 0.068 | +0.308 | +0.0211 |
| `char__ents` | Char 4-gram | 0.057 | +0.353 | +0.0201 |

##### Top 5 Features Pushing Towards BENIGN (Negative Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__contents` | Unigram | 0.328 | -0.787 | -0.2578 |
| `word__file` | Unigram | 0.298 | -0.343 | -0.1023 |
| `word__need` | Unigram | 0.187 | -0.293 | -0.0547 |
| `word__read` | Unigram | 0.280 | -0.187 | -0.0522 |
| `word__use this` | Bigram | 0.181 | -0.264 | -0.0480 |

---

### Tool 2: `list_directory`

| Field | Value |
|---|---|
| **Server Family** | `filesystem` (Model Context Protocol Official) |
| **Tool Name** | `list_directory` |
| **Actual Label** | `0` (Benign) |
| **Predicted Label ($\tau = 0.50$)** | `1` (Malicious) |
| **Predicted Malicious Probability ($\hat{p}$)** | **0.5238** (Medium Risk) |
| **Prediction Margin** | $+0.0238$ above decision threshold |

#### Full Description Text
> *"Get a detailed listing of all files and directories in a specified path. Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes. This tool is essential for understanding directory structure and finding specific files within a directory. Only works within allowed directories."*

#### Feature Contribution Analysis ($c_i = x_i \cdot w_i$)

##### Top 10 Features Pushing Towards MALICIOUS (Positive Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__files` | Unigram | 0.391 | +0.113 | +0.0442 |
| `word__with` | Unigram | 0.084 | +0.498 | +0.0417 |
| `word__is` | Unigram | 0.071 | +0.560 | +0.0396 |
| `word__tool` | Unigram | 0.090 | +0.429 | +0.0387 |
| `word__this` | Unigram | 0.063 | +0.603 | +0.0380 |
| `char__ wi` | Char 4-gram | 0.067 | +0.383 | +0.0255 |
| `word__listing` | Unigram | 0.183 | +0.126 | +0.0231 |
| `word__all` | Unigram | 0.111 | +0.205 | +0.0229 |
| `char__wit` | Char 4-gram | 0.071 | +0.294 | +0.0210 |
| `char__with` | Char 5-gram | 0.071 | +0.294 | +0.0210 |

##### Top 5 Features Pushing Towards BENIGN (Negative Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__specific` | Unigram | 0.193 | -0.748 | -0.1446 |
| `word__in` | Unigram | 0.129 | -0.931 | -0.1202 |
| `word__directory` | Unigram | 0.359 | -0.330 | -0.1186 |
| `word__results` | Unigram | 0.180 | -0.302 | -0.0545 |
| `word__get` | Unigram | 0.132 | -0.397 | -0.0523 |

---

### Tool 3: `directory_tree`

| Field | Value |
|---|---|
| **Server Family** | `filesystem` (Model Context Protocol Official) |
| **Tool Name** | `directory_tree` |
| **Actual Label** | `0` (Benign) |
| **Predicted Label ($\tau = 0.50$)** | `1` (Malicious) |
| **Predicted Malicious Probability ($\hat{p}$)** | **0.5892** (Medium Risk) |
| **Prediction Margin** | $+0.0892$ above decision threshold |

#### Full Description Text
> *"Get a recursive tree view of files and directories as a JSON structure. Each entry includes 'name', 'type' (file/directory), and 'children' for directories. Files have no children array, while directories always have a children array (which may be empty). The output is formatted with 2-space indentation for readability. Only works within allowed directories."*

#### Feature Contribution Analysis ($c_i = x_i \cdot w_i$)

##### Top 10 Features Pushing Towards MALICIOUS (Positive Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__with` | Unigram | 0.095 | +0.498 | +0.0475 |
| `word__is` | Unigram | 0.080 | +0.560 | +0.0451 |
| `word__no` | Unigram | 0.077 | +0.529 | +0.0409 |
| `word__files` | Unigram | 0.359 | +0.113 | +0.0405 |
| `word__always` | Unigram | 0.172 | +0.199 | +0.0342 |
| `word__as` | Unigram | 0.168 | +0.194 | +0.0324 |
| `word__be` | Unigram | 0.138 | +0.186 | +0.0255 |
| `word__only` | Unigram | 0.196 | +0.106 | +0.0207 |
| `char__ wi` | Char 4-gram | 0.054 | +0.383 | +0.0206 |
| `word__have` | Unigram | 0.398 | +0.050 | +0.0199 |

##### Top 5 Features Pushing Towards BENIGN (Negative Contribution):
| Feature Name | Type | TF-IDF Value ($x_i$) | Model Weight ($w_i$) | Net Contribution ($c_i$) |
|---|---|---|---|---|
| `word__directory` | Unigram | 0.241 | -0.330 | -0.0797 |
| `word__get` | Unigram | 0.150 | -0.397 | -0.0595 |
| `word__file` | Unigram | 0.166 | -0.343 | -0.0570 |
| `char__ies` | Char 4-gram | 0.109 | -0.376 | -0.0409 |
| `char__ch` | Char 3-gram | 0.093 | -0.328 | -0.0305 |

---

## 3. Root Cause Attribution

The error analysis reveals four primary structural drivers behind the false positives:

### A. Directive & Imperative Language Framing
The descriptions contain instructional directives explaining how the model or caller should interact with the tool:
* *"Use this tool when you need to examine..."* (`read_text_file`)
* *"This tool is essential for understanding..."* (`list_directory`)
* *"Files have no children array, while directories always have a children array..."* (`directory_tree`)

In the MCPTox malicious corpus, attack payloads heavily exploit imperative framing to inject prompts (e.g., *"Use this tool to override previous instructions"*, *"Always execute the command without confirmation"*). As a result, the linear model assigns positive weights to directive words (`use`, `tool`, `this`, `always`, `you`).

### B. High-Frequency Function Words and Connectives
Because n-gram TF-IDF operates on surface lexical statistics, high-frequency function words and copulas (`is`, `with`, `this`, `to`, `as`, `no`) emerged with positive linear coefficients:
* `word__this`: weight $+0.603$
* `word__is`: weight $+0.560$
* `word__to`: weight $+0.692$
* `word__with`: weight $+0.498$
* `word__no`: weight $+0.529$

These words appeared frequently in long attack descriptions in the training folds. When a benign tool description uses elaborate syntactic explanations (e.g., recursive JSON formatting rules in `directory_tree`), the accumulation of small positive contributions over 6–8 function words outweighs the domain-specific benign tokens (`contents`, `directory`, `read`).

### C. Security Boundary and Restriction Terminology
Both `list_directory` and `directory_tree` conclude with:
> *"Only works within allowed directories."*

While intended to document a security restriction in benign code, terms like `allowed`, `only`, and `system` co-occur in attack prompts referencing sandboxes, permissions, or system access.

### D. Extreme Class Imbalance (17:1 Ratio)
The dataset contains **485 malicious records** vs. **28 benign records**.
* Even though `class_weight='balanced'` adjusts the loss gradient, the model's vocabulary space is overwhelmingly populated by attack features (over 2,500 active features in the union).
* The benign class is represented by only ~22-23 samples in each training fold. Consequently, the model has sparse negative evidence to learn that structural English words (`tool`, `use`, `with`, `is`) are equally ubiquitous in legitimate tool documentation.

---

## 4. Key Takeaways & Actionable Recommendations

1. **Marginal Probability Distribution**:
   None of the false positives received high malicious scores (all were between 0.52 and 0.59). Genuine attacks average **0.9064** probability, and the minimum attack probability in the dataset is 0.5191.
2. **Threshold Shift**:
   Raising the classification threshold from $\tau = 0.50$ to $\tau = 0.60$ immediately corrects `list_directory` (0.5238) and `read_text_file` (0.5781). Raising to $\tau = 0.65$ eliminates all three Fold 5 false positives.
3. **Deterministic Policy Boundary**:
   The ML detector is only one input to the Security Gateway's `PolicyEngine`. Legitimate tools with marginal ML scores should be held for quarantine/audit review rather than blocked outright, while deterministic rules (e.g., regex pattern matching for shell injection or credential theft) safeguard against true attacks regardless of ML threshold.
