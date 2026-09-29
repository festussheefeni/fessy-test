import pandas as pd


def read_csv_ts(path, ts_col="timestamp"):
    df = pd.read_csv(path)
    df[ts_col] = pd.to_datetime(df[ts_col], format="ISO8601")
    return df
