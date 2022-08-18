#include "PCAP.h"
#include <fstream>

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


PCAPReader::PCAPReader(const std::string& fileName)
  : m_fileName(fileName),
  m_file_state(0),
  m_packet_count(0),
  m_payload_size(0)
{
  std::ifstream filestream(fileName, std::ios::binary);
  if (filestream.fail()) {
    return;
  }
  
  uint32_t magic_number(0);

  filestream.read((char*)&magic_number, sizeof(uint32_t));
  switch (magic_number) {
  case 0xa1b2c3d4:
    m_file_state = 1;
    break;
  case 0xd4c3b2a1:
    m_file_state = 2;
    break;
  default:
    return;
  }

  pcap_hdr_t global_header = {};
  filestream.read((char*)&global_header, 24); // читаем global header

  while (!filestream.eof())
  {
    pcaprec_hdr_t packet_header = {};
    filestream.read((char*)&packet_header, 16); // читаем packet header

    // изменяем порядок байт, если это необходимо
    // https://www.quora.com/How-do-you-reverse-a-byte-order-in-C
    if (m_file_state == 2) {
      packet_header.incl_len =
        ((packet_header.incl_len >> 24) & 0x000000FFul) |
        ((packet_header.incl_len >> 8) & 0x0000FF00ul) |
        ((packet_header.incl_len << 8) & 0x00FF0000ul) |
        ((packet_header.incl_len << 24) & 0xFF000000ul);
    }
    // читаем пакет, пока без обработки
    filestream.ignore(packet_header.incl_len);
    
    // увеличиваем значение переменных кол-ва пакетов и длины полезной информации
    m_packet_count++;
    m_payload_size += packet_header.incl_len;
  }
}


uint64_t PCAPReader::packetsCount() const
{
  if (m_file_state == 0) {
    return (uint64_t)-1;
  }

  return m_packet_count;
}


uint64_t PCAPReader::payloadSize() const
{
  if (m_file_state == 0) {
    return (uint64_t)-1;
  }

  return m_payload_size;
}
