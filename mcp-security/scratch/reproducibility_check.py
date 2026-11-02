import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import StratifiedGroupKFold

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
TRAINING_DIR = PROJECT_ROOT / "training"

def audit():
    print("=== REPRODUCIBILITY AUDIT ===")
    
    # 1. Dataset verification
    csv_path = DATA_DIR / "expanded_experimental_dataset.csv"
    df = pd.read_csv(csv_path)
    total_records = len(df)
    mal_count = int((df["label"] == 1).sum())
    benign_count = int((df["label"] == 0).sum())
    
    print(f"Dataset path: {csv_path}")
    print(f"Total rows: {total_records}")
    print(f"Malicious: {mal_count}, Benign: {benign_count}")
    print(f"Missing descriptions: {df['description'].isnull().sum()}")
    print(f"Empty/whitespace descriptions: {(df['description'].str.strip() == '').sum()}")
    print(f"Unique descriptions: {df['description'].nunique()}")
    print(f"Unique record_ids: {df['record_id'].nunique()}")
    print(f"Canonical groups count: {df['canonical_group'].nunique()}")
    
    # Check labels strictly binary
    unique_labels = sorted(df["label"].unique().tolist())
    print(f"Unique labels: {unique_labels}")
    assert unique_labels == [0, 1]
    
    # 2. Check OOD dataset
    ood_path = DATA_DIR / "expanded_ood_dataset.json"
    with open(ood_path, "r", encoding="utf-8") as f:
        ood_json = json.load(f)
    ood_records = ood_json["records"]
    print(f"OOD records count: {len(ood_records)}")
    ood_descriptions = [r["tool_description"] for r in ood_records]
    overlap_ood = df[df["description"].isin(ood_descriptions)]
    print(f"OOD overlap with training dataset: {len(overlap_ood)}")
    assert len(overlap_ood) == 0
    
    # 3. StratifiedGroupKFold disjointness
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    for fold_idx, (train_idx, val_idx) in enumerate(sgkf.split(df, y=df["label"], groups=df["canonical_group"])):
        train_groups = set(df.iloc[train_idx]["canonical_group"])
        val_groups = set(df.iloc[val_idx]["canonical_group"])
        overlap = train_groups.intersection(val_groups)
        assert len(overlap) == 0, f"Fold {fold_idx+1} group overlap: {overlap}"
    print("5-fold StratifiedGroupKFold: Strictly group-disjoint (0 overlap across all folds).")
    
    # 4. Independent test set disjointness
    TEST_BENIGN_SERVERS = ["puppeteer", "slack", "gitlab"]
    malicious_groups = df[df["label"] == 1]["canonical_group"].unique()
    np.random.seed(42)
    test_mal_groups = np.random.choice(malicious_groups, size=int(len(malicious_groups) * 0.20), replace=False)
    test_mask = (df["canonical_group"].isin(TEST_BENIGN_SERVERS)) | (df["canonical_group"].isin(test_mal_groups))
    dev_df = df[~test_mask]
    test_df = df[test_mask]
    dev_g = set(dev_df["canonical_group"])
    test_g = set(test_df["canonical_group"])
    overlap_indep = dev_g.intersection(test_g)
    print(f"Independent test split: Dev groups={len(dev_g)}, Test groups={len(test_g)}, Overlap={len(overlap_indep)}")
    assert len(overlap_indep) == 0
    
    # 5. Text similarity & near-duplicate check
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2)
    X = vec.fit_transform(df["description"])
    sim = cosine_similarity(X)
    np.fill_diagonal(sim, 0.0)
    
    cross_label_pairs = []
    same_label_pairs = []
    for i in range(len(df)):
        for j in range(i + 1, len(df)):
            score = sim[i, j]
            if score >= 0.80:
                is_cross = (df.iloc[i]["label"] != df.iloc[j]["label"])
                item = (i, j, float(score), df.iloc[i]["tool_name"], df.iloc[j]["tool_name"], df.iloc[i]["label"], df.iloc[j]["label"])
                if is_cross:
                    cross_label_pairs.append(item)
                else:
                    same_label_pairs.append(item)
                    
    print(f"Near-duplicate pairs (cos sim >= 0.80): same-label={len(same_label_pairs)}, cross-label={len(cross_label_pairs)}")
    if cross_label_pairs:
        print("Cross-label near duplicates found:")
        for p in cross_label_pairs[:5]:
            print(f"  Sim {p[2]:.3f}: {p[3]} (L={p[5]}) vs {p[4]} (L={p[6]})")
            
    # 6. Artifact verification
    model_path = MODELS_DIR / "expanded_detector_model.joblib"
    vec_path = MODELS_DIR / "expanded_vectorizer.joblib"
    print(f"Model artifact exists: {model_path.exists()} ({model_path.stat().st_size} bytes)")
    print(f"Vectorizer artifact exists: {vec_path.exists()} ({vec_path.stat().st_size} bytes)")
    
    model = joblib.load(model_path)
    vectorizer = joblib.load(vec_path)
    
    print(f"Model class: {model.__class__.__name__}")
    print(f"Model C: {model.C}, class_weight: {model.class_weight}, random_state: {model.random_state}")
    print(f"Model coef_ shape: {model.coef_.shape}, intercept_: {model.intercept_}")
    
    # Check feature union
    transformer_names = [name for name, _ in vectorizer.transformer_list]
    print(f"Vectorizer transformers: {transformer_names}")
    word_tr = dict(vectorizer.transformer_list)["word"]
    char_tr = dict(vectorizer.transformer_list)["char"]
    print(f"Word TF-IDF: ngram_range={word_tr.ngram_range}, max_features={word_tr.max_features}, sublinear_tf={word_tr.sublinear_tf}")
    print(f"Char TF-IDF: analyzer={char_tr.analyzer}, ngram_range={char_tr.ngram_range}, max_features={char_tr.max_features}, sublinear_tf={char_tr.sublinear_tf}")
    
    # 7. Check NaN in split report
    split_rep_path = TRAINING_DIR / "expanded_dataset_split_report.json"
    with open(split_rep_path, "r", encoding="utf-8") as f:
        split_rep = json.load(f)
    held_out_tools = split_rep["split_architecture"]["planned_independent_test_split"]["held_out_benign_tools"]
    nan_count = sum(1 for t in held_out_tools if t is None or (isinstance(t, float) and np.isnan(t)))
    print(f"NaN / None in held_out_benign_tools in split report: {nan_count}")

if __name__ == "__main__":
    audit()
