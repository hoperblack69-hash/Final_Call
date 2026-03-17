import torch
from torch.utils.data import Dataset
import pandas as pd
import numpy as np
from transformers import AutoTokenizer

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
        Simulates adversarial evasion tactics: URL shortening or random character injection (noise).
        """
        # Simplistic evasion: randomly inject '%' to simulate encoding noise 10% of the time during training
        if np.random.rand() < 0.1:
            if len(url) > 10:
                idx = np.random.randint(5, len(url) - 1)
                url = url[:idx] + "%20" + url[idx:]
        return url

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
