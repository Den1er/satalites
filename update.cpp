const int SATSUM = 48;
int LinkTable_Forward[SATSUM][4];
int LinkTable_Reverse[SATSUM][4];
bool Emissioned[SATSUM];
int Link_Index[SATSUM][SATSUM];
//int Port_Forward[SATSUM][SATSUM];
//int Port_Reverse[SATSUM][SATSUM];
void AllocateIndex(int SATNUM)
{
    int i = 0;
    for(int j = 0; j<SATNUM-1; ++j)
    {
        if(Emissioned[j]==1)
        {
            if((((opspf->st[i].STC.lat) - (opspf->oldst[i].STC.lat)) >= 0) || (opspf->isfirst_allocate == 1))
            {
                opspf->isfirst_allocate=0;
                for(int k = 0; k<4; ++k )
                {
                    if(LinkTable_Forward[j][k] != -1 && LinkTable_Forward[j][k]>j && Emissioned[k] == 1 )
                    {
                        Link_Index[j][k] = i++;
                    }
                }
            }
            else
            {
                for(int k = 0; k<4; ++k )
                {
                    if(LinkTable_Reverse[j][k] != -1 && LinkTable_Reverse[j][k]>j && Emissioned[k] == 1)
                    {
                        Link_Index[j][k] = i++;
                    }
                }
            }
        }
    }
}