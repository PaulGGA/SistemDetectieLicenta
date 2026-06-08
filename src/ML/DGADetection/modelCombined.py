import torch.nn


# clasa pentru modelul CNN + LSTM


class CNNLSTM(torch.nn.Module):
    def __init__(self, embededDim = 32, nrFilter = 128, lotmHidden = 64, vocabularDim = 41) -> None:
        super(CNNLSTM, self).__init__()

        self.layerEmbeding = torch.nn.Embedding(vocabularDim,embededDim, padding_idx= 0)

        self.layerConv = torch.nn.Conv1d(embededDim,nrFilter,4,padding= 1)

        self.relu = torch.nn.ReLU()

        self.sigmoid = torch.nn.Sigmoid()

        self.pool = torch.nn.MaxPool1d(2)

        self.layerLSTM = torch.nn.LSTM(nrFilter,lotmHidden,num_layers= 1, batch_first= True, bidirectional= True) 

        self.layerFinal = torch.nn.Linear(lotmHidden *2,1)



    def forward(self,x):
        
        x = self.layerEmbeding(x).permute(0,2,1)

        x = self.layerConv(x)

        x = self.relu(x)

        x = self.pool(x).permute(0,2,1)

        _, (output,_) = self.layerLSTM(x)

        ouputF = output[0, :, :]
        outputB = output[1, :, :]

        ouputTotal = torch.cat((ouputF,outputB),dim=1)

        return self.sigmoid(self.layerFinal(ouputTotal)).squeeze()

