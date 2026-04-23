import AsyncLock from "async-lock";
import fs from "fs";
import jwt from "jsonwebtoken";
import { Redis } from "@upstash/redis";
import { AccessError, InputError } from "./error.js";

const lock = new AsyncLock();

const JWT_SECRET = "llamallamaduck";
const DATABASE_FILE = "./database.json";
const { USE_REDIS } = process.env;

const redis = USE_REDIS ? Redis.fromEnv() : null;
/***************************************************************
                       State Management
***************************************************************/

let admins = {};

const update = async (admins) =>
  new Promise((resolve, reject) => {
    lock.acquire("saveData", async () => {
      try {
        if (USE_REDIS) {
          // Store to Upstash Redis
          await redis.set("admins", JSON.stringify({ admins }));
        } else {
          // Store to local file system
          fs.writeFileSync(
            DATABASE_FILE,
            JSON.stringify(
              {
                admins,
              },
              null,
              2
            )
          );
        }
        resolve();
      } catch(error) {
        console.log(error);
        reject(new Error("Writing to database failed"));
      }
    });
  });

export const save = () => update(admins);
export const reset = () => {
  update({});
  admins = {};
};

try {
  if (USE_REDIS) {
    // Read from Upstash Redis
    const data = await redis.get("admins");
    if (data) {
      const parsed = typeof data === "string" ? JSON.parse(data) : data;
      admins = parsed["admins"] ?? {};
    } else {
      // No data yet, initialise
      await save();
    }
  } else {
    // Read from local file
    const data = JSON.parse(fs.readFileSync(DATABASE_FILE));
    admins = data.admins;
  }
} catch(error) {
  console.log("WARNING: No database found, create a new one");
  save();
}

/***************************************************************
                       Helper Functions
***************************************************************/

export const userLock = (callback) =>
  new Promise((resolve, reject) => {
    lock.acquire("userAuthLock", callback(resolve, reject));
  });

/***************************************************************
                       Auth Functions
***************************************************************/

export const getEmailFromAuthorization = (authorization) => {
  try {
    const token = authorization.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    if (!(email in admins)) {
      throw new AccessError("Invalid Token");
    }
    return email;
  } catch(error) {
    throw new AccessError("Invalid token");
  }
};

export const login = (email, password) =>
  userLock((resolve, reject) => {
    if (email in admins) {
      if (admins[email].password === password) {
        resolve(jwt.sign({ email }, JWT_SECRET, { algorithm: "HS256" }));
      }
    }
    reject(new InputError("Invalid username or password"));
  });

export const logout = (email) =>
  userLock((resolve, reject) => {
    admins[email].sessionActive = false;
    resolve();
  });

export const register = (email, password, name) =>
  userLock((resolve, reject) => {
    if (email in admins) {
      return reject(new InputError("Email address already registered"));
    }
    admins[email] = {
      name,
      password,
      store: {},
    };
    const token = jwt.sign({ email }, JWT_SECRET, { algorithm: "HS256" });
    resolve(token);
  });

/***************************************************************
                       Store Functions
***************************************************************/

export const getStore = (email) =>
  userLock((resolve, reject) => {
    resolve(admins[email].store);
  });

export const setStore = (email, store) =>
  userLock((resolve, reject) => {
    admins[email].store = store;
    resolve();
  });
