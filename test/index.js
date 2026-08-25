import { it } from '@paulmillr/jsbt/test.js';

import './groth16.test.js';
import './mimcsponge.test.js';
import './msm.test.js';
import './pedersen.test.js';
import './string-bigints.test.js';
import './witness.test.js';

it.runWhen(import.meta.url);
