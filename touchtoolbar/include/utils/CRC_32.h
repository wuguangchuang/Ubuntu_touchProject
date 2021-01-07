#ifndef __CRC_32_H
#define __CRC_32_H

class CCRC_32
{
public:
	CCRC_32();
	CCRC_32(unsigned long CrcValue);
	~CCRC_32();

	void Reset(void);
	unsigned long Calculate(const unsigned char * pData, unsigned int dataSize);
	unsigned long GetCrcResult(void);

private:
	unsigned long m_CrcTable[32 * 8];
	unsigned long m_CrcValue;

	void InitialCrcTable(void);
	unsigned long Reflect(unsigned long ref, unsigned char ch);

};

#endif
