import torch
import torch.nn as nn
from transformers import AutoModel

class URLTransformerChannel(nn.Module):
    def __init__(self, model_name="distilbert-base-uncased", freeze_base=True):
        super(URLTransformerChannel, self).__init__()
        self.transformer = AutoModel.from_pretrained(model_name)
        
        # Optionally freeze base transformer to save memory/compute
        if freeze_base:
            for param in self.transformer.parameters():
                param.requires_grad = False
                
        self.feature_extractor = nn.Sequential(
            nn.Linear(self.transformer.config.hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

    def forward(self, input_ids, attention_mask):
        outputs = self.transformer(input_ids=input_ids, attention_mask=attention_mask)
        # Use the [CLS] token representation (index 0)
        cls_output = outputs.last_hidden_state[:, 0, :]
        return self.feature_extractor(cls_output)


class CharCNNChannel(nn.Module):
    def __init__(self, vocab_size=128, embed_dim=64, num_filters=128):
        super(CharCNNChannel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        
        # Parallel CNN channels with different kernel sizes for hierarchical features
        self.conv1 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=5, padding=2)
        self.pool = nn.AdaptiveMaxPool1d(1)
        
        self.fc = nn.Sequential(
            nn.Linear(num_filters * 2, 256),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

    def forward(self, x):
        # x is (batch_size, seq_len)
        x = self.embedding(x) # (batch_size, seq_len, embed_dim)
        x = x.transpose(1, 2) # (batch_size, embed_dim, seq_len) for Conv1d
        
        c1 = torch.relu(self.conv1(x))
        c2 = torch.relu(self.conv2(x))
        
        p1 = self.pool(c1).squeeze(-1) # (batch_size, num_filters)
        p2 = self.pool(c2).squeeze(-1) # (batch_size, num_filters)
        
        concat = torch.cat((p1, p2), dim=1)
        return self.fc(concat)


class JSTraceLSTMChannel(nn.Module):
    def __init__(self, vocab_size=128, embed_dim=64, hidden_size=128):
        super(JSTraceLSTMChannel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(input_size=embed_dim, hidden_size=hidden_size, batch_first=True, bidirectional=True)
        
        self.fc = nn.Sequential(
            nn.Linear(hidden_size * 2, 256), # Bidirectional doubles hidden size
            nn.ReLU(),
            nn.Dropout(0.3)
        )

    def forward(self, x):
        # x is (batch_size, seq_len)
        x = self.embedding(x)
        output, (hn, cn) = self.lstm(x)
        # Concatenate final hidden states from both directions
        hidden = torch.cat((hn[-2,:,:], hn[-1,:,:]), dim=1)
        return self.fc(hidden)


class MultiChannelFusionNetwork(nn.Module):
    def __init__(self, num_classes=3):
        """
        Multiclass: 0 = Benign, 1 = Phishing, 2 = Malware
        Fuses embeddings from LLM (256), CNN (256), and LSTM (256).
        Total fusion dimension = 768
        """
        super(MultiChannelFusionNetwork, self).__init__()
        
        # 1. Channels
        self.llm_channel = URLTransformerChannel()
        self.cnn_channel = CharCNNChannel()
        self.js_channel = JSTraceLSTMChannel()
        
        # 2. Modality Fusion Layer
        self.fusion = nn.Sequential(
            nn.Linear(256 + 256 + 256, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(512, 128),
            nn.ReLU()
        )
        
        self.classifier = nn.Linear(128, num_classes)

    def forward(self, llm_ids, llm_mask, char_seq, js_seq):
        llm_feat = self.llm_channel(llm_ids, llm_mask)
        cnn_feat = self.cnn_channel(char_seq)
        js_feat = self.js_channel(js_seq)
        
        fused_features = torch.cat((llm_feat, cnn_feat, js_feat), dim=1)
        fused = self.fusion(fused_features)
        
        return self.classifier(fused)

if __name__ == "__main__":
    # Test Forward Pass Requirements
    print("Testing MultiChannelFusionNetwork Forward Pass...")
    model = MultiChannelFusionNetwork()
    
    # Dummy Tensors representing a batch size of 2
    batch_size = 2
    llm_ids = torch.randint(0, 30522, (batch_size, 200)) # distilbert vocab
    llm_mask = torch.ones((batch_size, 200))
    char_seq = torch.randint(0, 128, (batch_size, 200))
    js_seq = torch.randint(0, 128, (batch_size, 500))
    
    out = model(llm_ids, llm_mask, char_seq, js_seq)
    print("Output Shape:", out.shape) # Expected (2, 3) 
