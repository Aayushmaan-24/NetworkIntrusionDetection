# ML-Based Network Intrusion Detection System

**DBMS Mini Project (21CSC205P) – SRMIST**

**Team**: Aayushmaan Chakraborty & Shashank Prasad

This project implements a **machine learning-based network intrusion detection system** using the **NSL-KDD dataset** and **PostgreSQL** database.

## Project Overview

- Loads and cleans the NSL-KDD dataset (~125k records)
- Stores data in a normalized PostgreSQL database (18-column `connections` table)
- Maps categorical features (protocol, service, flag, attack) to lookup IDs
- Trains a Random Forest classifier → **99% accuracy** on test set
- Generates evaluation visuals (confusion matrix) and metrics

## Repository Contents

| File                        | Description                                                                              |
|-----------------------------|------------------------------------------------------------------------------------------|
| `Intrusion_Detection.ipynb` | Main Jupyter notebook: data loading, cleaning, DB insertion, model training & evaluation |
| `schema.sql`                | PostgreSQL schema (lookup tables + trimmed `connections` table)                          |
| `ER_diagram.png`            | Entity-Relationship diagram of the database schema                                       |
| `relational_table.png`      | Relational schema diagram (tables + relationships)                                       |
| `KDDTrain+.txt`             | Raw NSL-KDD training dataset (do NOT commit large data files to GitHub)                  |
| `confusion_matrix.png`      | Model performance visualization                                                          |
| `classification_report.txt` | Detailed metrics                                                                         |
| `Inrustion_Detection.pkl`   | Trained Random Forest model (saved with joblib) – ready for prediction                   |

**Note**: Large data files (`KDDTrain+.txt`) are ignored via `.gitignore` — download from [Kaggle NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) or [UNB site](https://www.unb.ca/cic/datasets/nsl.html) to reproduce.

## Tech Stack

- **Database**: PostgreSQL
- **Language**: Python 3
- **Libraries**: pandas, sqlalchemy, scikit-learn, matplotlib, seaborn, tqdm
- **Dataset**: NSL-KDD (KDDTrain+.txt)

## How to Reproduce

1. **Set up PostgreSQL**
   - Create database: `intrusion_db`
   - Run `schema.sql` to create tables

2. **Install dependencies**
   ```bash
   pip install pandas sqlalchemy psycopg2-binary scikit-learn matplotlib seaborn tqdm

3. **Download dataset**  
  - Place KDDTrain+.txt in the project folder (or update CSV_PATH in notebook)

4. **Run notebook**  
  - Open Intrusion_Detection.ipynb
  - Update DB_PASS (and path if needed)
  - Run all cells sequentially

5. **Expected Output**  
  - ~125k rows loaded
  - ~80k rows inserted after cleaning/mapping
  - Random Forest accuracy: ~99%


## Results  
  - Model: Random Forest Classifier (n_estimators=100)
  - Accuracy: 99% on test set
  - Visuals: Confusion matrix & classification report saved in notebook outputs

## License  
  - MIT License – feel free to use for educational purposes (cite NSL-KDD dataset)

## References  
  - NSL-KDD Dataset: https://www.unb.ca/cic/datasets/nsl.html
  - Kaggle Mirror: https://www.kaggle.com/datasets/hassan06/nslkdd
