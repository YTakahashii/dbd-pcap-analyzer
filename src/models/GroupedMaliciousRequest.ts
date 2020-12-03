import { Packet } from './Packet';

export type GroupedMaliciousRequest = {
  entranceUrl: string;
  requests: Packet[];
  responses: Packet[];
  requestsCount: number;
  responseCount: number;
};
