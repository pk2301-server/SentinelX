import axios from "axios";

const API = axios.create({
  baseURL: "https://sentinelxpk.onrender.com/api",
});

export default API;