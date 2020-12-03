import { GroupedMaliciousRequest } from '../models/GroupedMaliciousRequest';

export function aggregateWebHierarchy(groupedPacketPair: GroupedMaliciousRequest) {
  const webHierarchy = groupedPacketPair.responses.reduce((hierarchy, response) => {
    const isMovedPermanently301 = !!response._source?.layers?.http?.['HTTP/1.1 301 Moved Permanently\\r\\n'];
    const isFound302 = !!response._source?.layers?.http?.['HTTP/1.1 302 Found\\r\\n'];
    const isRedirectResponse = isMovedPermanently301 || isFound302;
    if (isRedirectResponse) {
      return hierarchy + 1;
    }
    return hierarchy;
  }, 0);

  return webHierarchy;
}
