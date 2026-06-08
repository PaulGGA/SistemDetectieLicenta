import torch
from torch.utils.data import Dataset

# creare dataset pentru modelul Deep

class datasetLong(Dataset):
    def __init__(self,domains, labels, dictionar : dict):
        self.labels = labels

        if labels is not None:
            self.labels = labels.reset_index(drop= True)
        
        self.domains = domains.reset_index(drop=True)
        
        self.dictionar = dictionar
        self.cntDate = len(domains)

    def __len__(self):
        return self.cntDate

    def __getitem__(self, key):
        domain = str(self.domains[key]).lower()

        token = [self.dictionar.get(c,1) for c in domain]

        tensorToken = torch.tensor(token, dtype= torch.long)
        
        if self.labels is not None:
            tensorLabel = torch.tensor(self.labels[key], dtype= torch.float32)
            return tensorToken, tensorLabel

        return tensorToken
