import {expect} from 'chai';
const myapp = require(".");

describe('Testing printMsg function, should return "Hello World!" ', () => {
	it('Should Return Hello World!', () => {
         	expect(myapp.printMsg()).to.equal("Hello World!");
	});
});