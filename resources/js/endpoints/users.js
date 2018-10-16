import axios from 'axios';

let base = 'api/users/';

export default {
  list(params) {
    return axios.get(`${base}`, { params: params });
  },
  show(params) {
    return axios.get(`${base}${params.id}`, { params: params });
  },
  add(params) {
    return axios.post(`${base}`, params);
  },
  edit(params) {
    return axios.put(`${base}${params.id}`, params);
  },
  remove(params) {
    return axios.delete(`${base}${params.id}`, { params: params });
  },
};
