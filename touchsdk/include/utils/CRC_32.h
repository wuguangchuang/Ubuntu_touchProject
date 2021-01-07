#ifndef __CRC_32_H
#define __CRC_32_H

class CCRC_32
{
public:
	CCRC_32();
    CCRC_32(unsigned int CrcValue);
	~CCRC_32();

	void Reset(void);
    unsigned int Calculate(const unsigned char * pData, unsigned int dataSize);
    unsigned int GetCrcResult(void);

private:
    unsigned int m_CrcTable[32 * 8];
    unsigned int m_CrcValue;

	void InitialCrcTable(void);
    unsigned int Reflect(unsigned long ref, unsigned char ch);

};

#endif
