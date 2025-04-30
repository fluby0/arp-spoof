#include <iostream>
#include <cstdint>
#include "ip.h"

// IP 헤더 구조체 정의
struct IPHeader {
    uint8_t version : 4;         // 버전
    uint8_t headerLength : 4;    // 헤더 길이
    uint8_t typeOfService;       // 타입 서비스
    uint16_t totalLength;        // 전체 길이
    uint16_t identification;     // 식별자
    uint16_t flagsAndFragmentOffset; // 플래그와 프래그먼트 오프셋
    uint8_t timeToLive;          // TTL
    uint8_t protocol;            // 프로토콜
    uint16_t headerChecksum;     // 헤더 체크섬
    Ip sourceAddress;      // 출발지 IP 주소
    Ip destinationAddress; // 목적지 IP 주소
};
typedef IPHeader *PIPHeader;
