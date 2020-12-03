import { Packet } from './models/Packet';
import { GroupedMaliciousRequest } from './models/GroupedMaliciousRequest';

export function groupPerMaliciousTraffic(pcapPackets: Packet[], entranceUrlList: string[]): GroupedMaliciousRequest[] {
  const groupedPackets: GroupedMaliciousRequest[] = [];
  for (const entranceUrl of entranceUrlList) {
    const requestPackets = pcapPackets.filter((packet) => {
      const referer = packet._source?.layers?.http?.['http.referer'];
      if (!referer) {
        return false;
      }
      return referer === entranceUrl;
    });
    const responsePackets = requestPackets.reduce<Packet[]>((responses, requestPacket) => {
      const responseFrameNumber = requestPacket._source?.layers?.http?.['http.response_in'];
      const responsePacket = pcapPackets.find((packet) => {
        const httpResponseIn = packet._source?.layers?.http?.['http.response_in'];
        return httpResponseIn && httpResponseIn === responseFrameNumber;
      });
      if (responsePacket) {
        return [...responses, responsePacket];
      } else {
        return responses;
      }
    }, []);
    groupedPackets.push({
      entranceUrl,
      requests: extractAttributes(requestPackets),
      responses: extractAttributes(responsePackets),
    });
  }

  return groupedPackets;
}

// 必要な属性だけ取り出す
function extractAttributes(packets: Packet[]) {
  return packets.map((packet) => ({
    _index: packet._index,
    ...packet._source?.layers?.frame,
    'ip.src': packet._source?.layers?.ip?.['ip.src'],
    'ip.dst': packet._source?.layers?.ip?.['ip.dst'],
    ...packet._source?.layers?.http,
  }));
}
