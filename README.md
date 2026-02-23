# ML-Based Network Intrusion Detection System

**DBMS Mini Project (21CSC205P) – SRMIST**

**Team**: Aayushmaan Chakraborty & Shashank Prasad

**Technologies**:
- PostgreSQL (database)
- NSL-KDD dataset
- Python (pandas, scikit-learn, matplotlib, seaborn)
- Jupyter Notebook

**Key Achievements**:
- Loaded & cleaned NSL-KDD dataset (80,077 rows after preprocessing)
- Inserted into PostgreSQL with trimmed 18-column schema
- Trained Random Forest Classifier → **99% accuracy**

**Files**:
- `Intrusion_Detection.ipynb` → full workflow (schema, data prep, DB insertion, model training, evaluation)
- `schema.sql` → PostgreSQL schema
- `confusion_matrix.png` → model performance visualization
- `classification_report.txt` → detailed metrics

**How to run**:
1. Set up PostgreSQL with `schema.sql`
2. Run notebook cells sequentially
3. Model achieves 99% accuracy on test set

**Next steps**:
- Binary classification (normal vs attack)
- Flask API for real-time prediction
- Complex queries, triggers, views
