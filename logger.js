import { fileURLToPath } from 'url';
import path from 'path';
import pkg from 'log4js';
const { getLogger, configure } = pkg;

// 将 URL 转换为文件路径
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 使用 log4js
configure({
    appenders: {
        console: { type: 'console' },
    },
    categories: {
        default: { appenders: ['console'], level: 'debug' },
    },
});

export default getLogger
