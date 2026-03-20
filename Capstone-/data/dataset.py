import torch
from torch.utils.data import Dataset
import pandas as pd
import numpy as np
from transformers import AutoTokenizer
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote_plus
import random


def load_openphish_csv(csv_path: str) -> pd.DataFrame:
    """
    Load OpenPhish dataset from CSV file.
    
    Expected CSV format: Contains 'url' column (and optionally status columns).
    Maps all entries as phishing (label=1).
    Adds placeholder js_trace for compatibility with multi-modal pipeline.
    
    Args:
        csv_path (str): Path to OpenPhish CSV file.
        
    Returns:
        pd.DataFrame: DataFrame with columns ['url', 'js_trace', 'label'] formatted for training.
    """
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"OpenPhish CSV not found: {csv_path}")
    except Exception as e:
        raise ValueError(f"Error reading CSV {csv_path}: {e}")
    
    # Ensure 'url' column exists
    if 'url' not in df.columns:
        raise ValueError(f"CSV must contain 'url' column. Found columns: {df.columns.tolist()}")
    
    # Clean URLs: remove whitespace and filter invalid entries
    df['url'] = df['url'].astype(str).str.strip()
    df = df[df['url'].str.len() > 0]
    
    # Map all OpenPhish entries as phishing (label=1)
    df['label'] = 1
    
    # Add placeholder js_trace (empty string for OpenPhish data without JS traces)
    df['js_trace'] = ""
    
    # Keep only required columns
    df = df[['url', 'js_trace', 'label']]
    
    return df


def load_iscx_csv(csv_path: str) -> pd.DataFrame:
    """
    Load ISCX-URL dataset from CSV file.

    Expected CSV format: Contains 'url' and 'label' columns.
    Label mapping: benign→0, phishing→1, malware→2, defacement→2
    Adds placeholder js_trace for compatibility with multi-modal pipeline.

    Args:
        csv_path (str): Path to ISCX-URL CSV file.

    Returns:
        pd.DataFrame: DataFrame with columns ['url', 'js_trace', 'label'] formatted for training.
    """
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"ISCX-URL CSV not found: {csv_path}")
    except Exception as e:
        raise ValueError(f"Error reading ISCX-URL CSV {csv_path}: {e}")

    # Ensure required columns exist
    required_cols = ['url', 'label']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"ISCX-URL CSV must contain columns: {required_cols}. Missing: {missing_cols}")

    # Clean URLs: remove whitespace and filter invalid entries
    df['url'] = df['url'].astype(str).str.strip()
    df = df[df['url'].str.len() > 0]

    # Map ISCX labels to numeric labels
    label_mapping = {
        'benign': 0,
        'phishing': 1,
        'malware': 2,
        'defacement': 2  # Map defacement to malware category
    }

    df['label'] = df['label'].astype(str).str.lower().map(label_mapping)

    # Handle unmapped labels
    unmapped = df['label'].isna().sum()
    if unmapped > 0:
        print(f"Warning: {unmapped} entries in ISCX-URL CSV have unmapped labels, dropping them")
        df = df.dropna(subset=['label'])

    df['label'] = df['label'].astype(int)

    # Add placeholder js_trace (empty string for ISCX-URL data without JS traces)
    df['js_trace'] = ""

    # Keep only required columns
    df = df[['url', 'js_trace', 'label']]

    return df


def load_phishtank_csv(csv_path: str) -> pd.DataFrame:
    """
    Load PhishTank dataset from CSV file.

    Expected CSV format: Contains 'url', 'phish_detail_url', 'submission_time', 'verified' columns.
    All entries are phishing (label=1).
    Adds placeholder js_trace for compatibility with multi-modal pipeline.

    Args:
        csv_path (str): Path to PhishTank CSV file.

    Returns:
        pd.DataFrame: DataFrame with columns ['url', 'js_trace', 'label'] formatted for training.
    """
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        raise FileNotFoundError(f"PhishTank CSV not found: {csv_path}")
    except Exception as e:
        raise ValueError(f"Error reading PhishTank CSV {csv_path}: {e}")

    # Ensure 'url' column exists
    if 'url' not in df.columns:
        raise ValueError(f"PhishTank CSV must contain 'url' column. Found columns: {df.columns.tolist()}")

    # Clean URLs: remove whitespace and filter invalid entries
    df['url'] = df['url'].astype(str).str.strip()
    df = df[df['url'].str.len() > 0]

    # Map all PhishTank entries as phishing (label=1)
    df['label'] = 1

    # Add placeholder js_trace (empty string for PhishTank data without JS traces)
    df['js_trace'] = ""

    # Keep only required columns
    df = df[['url', 'js_trace', 'label']]

    return df


def merge_datasets(*datasets: pd.DataFrame) -> pd.DataFrame:
    """
    Merge multiple datasets into a single training dataset.
    All datasets must have columns: ['url', 'js_trace', 'label'].
    
    Args:
        *datasets: Variable number of DataFrames to merge.
        
    Returns:
        pd.DataFrame: Concatenated and shuffled dataset.
    """
    if not datasets:
        raise ValueError("At least one dataset must be provided.")
    
    merged = pd.concat(datasets, ignore_index=True)
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return merged


class PhishingMultiModalDataset(Dataset):
    """
    A PyTorch Dataset that loads multi-modal data for phishing detection.
    It expects a DataFrame with the following columns (at minimum):
      - 'url': The URL string.
      - 'js_trace': A string sequence or space-separated tokens representing Javascript execution traces/AST.
      - 'label': Integer label (e.g., 0 for Benign, 1 for Phishing, 2 for Malware).
    """
    def __init__(self, df: pd.DataFrame, llm_model_name: str = "distilbert-base-uncased", max_url_len: int = 200, max_js_len: int = 500, char_vocab_size: int = 128):
        self.df = df
        
        # Tokenizer for the LLM channel (URL tokenization)
        self.tokenizer = AutoTokenizer.from_pretrained(llm_model_name)
        
        self.max_url_len = max_url_len
        self.max_js_len = max_js_len
        self.char_vocab_size = char_vocab_size

    def __len__(self):
        return len(self.df)

    def _get_char_encoding(self, text, max_len):
        """
        Encodes a string into character indices for the CNN channel.
        Uses ASCII values up to char_vocab_size.
        """
        encoded = np.zeros(max_len, dtype=np.int64)
        for i, char in enumerate(text[:max_len]):
            val = ord(char)
            encoded[i] = val if val < self.char_vocab_size else 0 # 0 for unknown/out-of-vocab characters
        return torch.tensor(encoded, dtype=torch.long)

    def _simulate_evasion(self, url: str) -> str:
        """
        Simulates adversarial evasion tactics.

        Applies each tactic independently with ~10% probability:
        - percent-encoding noise (existing behavior)
        - subdomain flooding (inject random prefix labels)
        - homoglyph substitution (Latin→visually similar Unicode letters)
        - URL shortener wrapping (fake shortener redirect pattern)
        """

        def _add_percent_noise(u: str) -> str:
            if len(u) > 10:
                idx = np.random.randint(5, len(u) - 1)
                return u[:idx] + "%20" + u[idx:]
            return u

        def _subdomain_flood(u: str) -> str:
            parsed = urlparse(u if u.startswith(("http://", "https://")) else "http://" + u)
            host = parsed.hostname or ""
            if not host:
                return u

            prefixes = ["secure", "login", "verify", "update", "auth", "account"]
            chosen = random.choice(prefixes)
            extra = f"{chosen}.{random.choice(prefixes)}"

            # Preserve port if included
            port = f":{parsed.port}" if parsed.port else ""
            new_host = f"{extra}.{host}{port}"
            new_netloc = new_host
            if parsed.username:
                new_netloc = f"{parsed.username}@{new_netloc}"
            if parsed.password:
                new_netloc = f"{parsed.username}:{parsed.password}@{new_host}"

            return urlunparse((parsed.scheme or "http", new_netloc, parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""))

        def _homoglyph_sub(u: str) -> str:
            mapping = {
                "a": "а",  # Cyrillic a
                "e": "е",  # Cyrillic e
                "o": "о",  # Cyrillic o
                "i": "і",  # Cyrillic i
                "c": "с",  # Cyrillic c
                "p": "р",  # Cyrillic p
                "y": "у",  # Cyrillic y
                "s": "ѕ",  # Cyrillic s
                "x": "х",  # Cyrillic x
            }
            # Pick 1-2 replacments if possible
            candidates = [i for i, ch in enumerate(u) if ch.lower() in mapping]
            if not candidates:
                return u
            count = min(2, max(1, int(np.random.choice([1, 2]))))
            for idx in random.sample(candidates, min(count, len(candidates))):
                original = u[idx]
                repl = mapping.get(original.lower(), original)
                if original.isupper():
                    repl = repl.upper()
                u = u[:idx] + repl + u[idx+1:]
            return u

        def _shortener_wrap(u: str) -> str:
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly"]
            chosen = random.choice(shorteners)
            safe = quote_plus(u)
            suffix = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            return f"http://{chosen}/{suffix}?url={safe}"

        out_url = url

        if np.random.rand() < 0.1:
            out_url = _add_percent_noise(out_url)

        if np.random.rand() < 0.1:
            out_url = _subdomain_flood(out_url)

        if np.random.rand() < 0.1:
            out_url = _homoglyph_sub(out_url)

        if np.random.rand() < 0.1:
            out_url = _shortener_wrap(out_url)

        return out_url

    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        
        raw_url = str(row['url'])
        # Apply data augmentation (adversarial training)
        augmented_url = self._simulate_evasion(raw_url)
        
        # 1. LLM Channel Input (Tokenized URL)
        encoded_url_llm = self.tokenizer(
            augmented_url,
            padding="max_length",
            truncation=True,
            max_length=self.max_url_len,
            return_tensors="pt"
        )
        
        # 2. CNN Channel Input (Character-level URL)
        encoded_url_char = self._get_char_encoding(augmented_url, self.max_url_len)
        
        # 3. JS sequential Trace input (Placeholder logic - would depend on actual feature extraction)
        raw_js = str(row.get('js_trace', ''))
        # For simplicity, we just character-encode the JS trace sequence for an LSTM/Transformer block
        encoded_js = self._get_char_encoding(raw_js, self.max_js_len)
        
        # Label
        label = torch.tensor(row['label'], dtype=torch.long)

        return {
            "llm_input_ids": encoded_url_llm["input_ids"].squeeze(0),
            "llm_attention_mask": encoded_url_llm["attention_mask"].squeeze(0),
            "char_seq": encoded_url_char,
            "js_seq": encoded_js,
            "label": label
        }

if __name__ == "__main__":
    # Quick test
    sample_data = pd.DataFrame({
        'url': ['http://example.com/login', 'http://malicious-site.net/verify'],
        'js_trace': ['var a=1; console.log(a);', 'eval(atob("c29tZW1hbGljaW91c2NvZGU="));'],
        'label': [0, 1]
    })
    
    dataset = PhishingMultiModalDataset(sample_data)
    sample = dataset[0]
    print("Sample keys:", sample.keys())
    print("LLM input shape:", sample['llm_input_ids'].shape)
    print("Char seq shape:", sample['char_seq'].shape)
    print("JS seq shape:", sample['js_seq'].shape)
    print("Label:", sample['label'])
    
    print("\n" + "="*70)
    print("EXAMPLE: Merging Synthetic Data + OpenPhish Dataset")
    print("="*70)
    print("\nTo integrate OpenPhish data into training:")
    print("  1. Save OpenPhish CSV with 'url' column")
    print("  2. Call: openphish_df = load_openphish_csv('path/to/openphish.csv')")
    print("  3. Merge: combined_df = merge_datasets(synthetic_df, openphish_df)")
    print("  4. Train: dataset = PhishingMultiModalDataset(combined_df)")
    print("\nExample code snippet:")
    print("  synthetic_df = pd.DataFrame({'url': [...], 'label': [...], 'js_trace': [...]})")
    print("  openphish_df = load_openphish_csv('openphish.csv')")
    print("  combined_df = merge_datasets(synthetic_df, openphish_df)")
    print("  training_dataset = PhishingMultiModalDataset(combined_df)")
