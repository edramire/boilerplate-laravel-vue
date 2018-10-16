export function validateEmail (rule, value, callback) {
  console.log(rule)
  if (value === '') {
    callback(new Error('El email no puede estar vacío'));
  } else {
    let re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    let isValid = re.test(String(email).toLowerCase());
    if (!isValid) {
      callback(new Error('Formato de email incorrecto'));
    } else {
      callback();
    }
  }
};

export function notEmpty (rule, value, callback) {
  if (value === '') {
    callback(new Error('El email no puede estar vacío'));
  } else {
    callback();
  }
};
