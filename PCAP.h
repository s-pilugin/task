#pragma once

#include <string>


class PCAPReader {
    const std::string fileName;
public:
    explicit PCAPReader(const std::string &fileName);

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)
    uint64_t payloadSize() const;
};
