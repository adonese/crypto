import uuid from 'uuid';
import JSencrypt from "jsencrypt";

  function generateIPin(pin, key) {
    // do something
    let id = uuid.v4()
    let jsencrypt = new JSencrypt();
    jsencrypt.setPublicKey(key);
    let data = jsencrypt.encrypt(id + pin);
    console.log("the private key encrypted is: ", data)
    return [data, id]
  }