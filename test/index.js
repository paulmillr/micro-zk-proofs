import { should } from 'micro-should';

import './groth16.test.js';
import './mimcsponge.test.js';
import './msm.test.js';
import './pedersen.test.js';
import './witness.test.js';

should.runWhen(import.meta.url);
