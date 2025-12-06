import BN from 'bn.js';
import { eddsa as EDDSA } from 'elliptic';

import RedBN from './interfaces';

export const ec: EDDSA = new EDDSA('ed25519');

const { red } = ec.curve;

export const sqrtm1: RedBN = new BN('547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d', 'hex').toRed(red);
