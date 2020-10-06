function reqJSON(method, url, data) {
  return new Promise((resolve, reject) => {
    let xhr = new XMLHttpRequest();
    xhr.open(method, url);
	xhr.setRequestHeader('Content-type','application/json')
    xhr.responseType = 'json';
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve({status: xhr.status, statusText:xhr.statusText, data: xhr.response});
      } else {
	    console.error('xhr with error:',xhr);
        reject({status: xhr.status, statusText:xhr.statusText, data: xhr.response});
      }
    };
    xhr.onerror = () => {
	  console.error('xhr with error:',xhr);
      reject({status: xhr.status,statusText:xhr.statusText, data: xhr.response});
    };
    xhr.send(JSON.stringify(data));
	//xhr.send(data);
  });
}
