import { Response } from 'express';

export const getCurrentMs = (): number => {
    return Math.floor(Date.now() / 1000);
};

export const success = (res: Response, message: string, data: any = null): Response => {
    return res.json({
        data,
        code: 200,
        success: true,
        message
    });
};

export const error = (res: Response, message: string, code: number, data: any = null): Response => {
    return res.status(code).json({
        data,
        code,
        success: false,
        message
    });
};