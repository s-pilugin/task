#pragma once
#include <string>

class PCAPReader {
    const std::string m_fileName;
    // 0 = invalid; 1 = identical, 2 = swapped
    uint8_t m_file_state;
    uint64_t m_packet_count;
    uint64_t m_payload_size;
public:
    explicit PCAPReader(const std::string &fileName);

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)
    uint64_t payloadSize() const;
};
