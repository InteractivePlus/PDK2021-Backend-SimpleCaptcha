import {CaptchaFactory, CaptchaFactoryInstallInfo} from '@interactiveplus/pdk2021-backendcore/dist/AbstractFactoryTypes/Captcha/CaptchaFactory';
import { BackendCaptchaSystemSetting } from '../../PDK2021-BackendCore/dist/AbstractDataTypes/SystemSetting/BackendCaptchaSystemSetting';
import { MaskUID } from '../../pdk2021-common/dist/AbstractDataTypes/MaskID/MaskIDEntity';
import { APPClientID } from '../../pdk2021-common/dist/AbstractDataTypes/RegisteredAPP/APPEntityFormat';
import { UserEntityUID } from '../../pdk2021-common/dist/AbstractDataTypes/User/UserEntity';
import SVGCaptcha from 'svg-captcha';
import sharp from 'sharp';
import { Base64 } from 'js-base64';
import { parseIPAddr } from './IpAddrUtil';

interface SimpleCaptchaInfo{
    captcha_id: string,
    imageJpegB64: string
}

interface SimpleCaptchaVerifyInfo{
    captcha_id: string,
    captcha_ans: string
}

export type {SimpleCaptchaInfo, SimpleCaptchaVerifyInfo};

interface SimpleCaptchaCreateInfo{
    isDarkMode?: boolean
}

export type {SimpleCaptchaCreateInfo};

interface SimpleCaptchaEntity{
    captcha_id: string,
    client_id: APPClientID | null,
    mask_uid?: MaskUID,
    uid?: UserEntityUID,
    ip_address: string,
    captcha_ans: string
}

export type {SimpleCaptchaEntity};

interface SimpleCaptchaFactoryStorage{
    putCaptcha(createInfo : {[key in keyof SimpleCaptchaEntity as Exclude<key,'captcha_id'>]:SimpleCaptchaEntity[key]}, captchaIDLen : number) : Promise<SimpleCaptchaEntity>;
    getCaptcha(captchaId: string) : Promise<SimpleCaptchaEntity | undefined>;
    useCaptcha(captchaId: string) : Promise<void>;

    clearOutdatedAndUsedCaptchas() : Promise<void>;
    install(params: CaptchaFactoryInstallInfo, captchaIDLen : number, captchaAnsLen: number) : Promise<void>;
    uninstall() : Promise<void>;
    clearData() : Promise<void>;
}

export type {SimpleCaptchaFactoryStorage};

class SimpleCaptchaFactory implements CaptchaFactory<SimpleCaptchaInfo,SimpleCaptchaVerifyInfo, SimpleCaptchaCreateInfo>{
    constructor(public storageEngine : SimpleCaptchaFactoryStorage, protected backendCaptchaSystemSetting : BackendCaptchaSystemSetting, public publicKey : string, public privateKey : string, public signAlgorithm: 'RS256' | 'RS384' | 'RS512', public hashSalt : string){

    }
    
    getCaptchaIDLen() : number{
        return 15;
    }
    getCaptchaAnsLen() : number{
        return 5;
    }
    getCaptchaSystemSetting(): BackendCaptchaSystemSetting {
        return this.backendCaptchaSystemSetting;
    }
    async generateCaptcha(client_id: APPClientID | null, ipAddress : string, mask_uid?: MaskUID, uid?: UserEntityUID, isDarkMode?: boolean) : Promise<SimpleCaptchaInfo>{
        let captcha = SVGCaptcha.create({size:this.getCaptchaAnsLen(),ignoreChars:'0o1i',noise:2})
        let sharpObj = sharp(captcha.data);
        if(isDarkMode){
            sharpObj = sharpObj.negate();
        }
        let generatedBase64JPEG : string | undefined = undefined;
        {
            let outputJPEG = await (await sharpObj.jpeg({mozjpeg:true}).toBuffer());
            let outputJPEGBufArray = new Uint8Array(outputJPEG.buffer);
            generatedBase64JPEG = Base64.fromUint8Array(outputJPEGBufArray);
        }

        
        let putInfo = {
            client_id: client_id,
            mask_uid: mask_uid,
            ip_address: ipAddress,
            uid: uid,
            captcha_ans: captcha.text
        };

        let returendVal = await this.storageEngine.putCaptcha(putInfo,this.getCaptchaIDLen());
        return {
            captcha_id: returendVal.captcha_id,
            imageJpegB64: generatedBase64JPEG
        };
    }
    async generateCaptchaWithAPP(createInfo: SimpleCaptchaCreateInfo, client_id: APPClientID, ipAddress: string, mask_uid?: MaskUID): Promise<SimpleCaptchaInfo> {
        return await this.generateCaptcha(client_id,ipAddress,mask_uid,undefined,createInfo.isDarkMode);
    }
    async generateCaptchaWithPDK(createInfo: SimpleCaptchaCreateInfo, ipAddress: string, user_uid?: UserEntityUID): Promise<SimpleCaptchaInfo> {
        return await this.generateCaptcha(null,ipAddress,undefined,user_uid,createInfo.isDarkMode);
    }
    async verifyCaptcha(verifyInfo: SimpleCaptchaVerifyInfo, ipAddress: string, clientID?: string | null, user_uid?: UserEntityUID, mask_uid?: MaskUID): Promise<boolean> {
        let gotCaptcha = await this.storageEngine.getCaptcha(verifyInfo.captcha_id);
        if(gotCaptcha === undefined){
            return false;
        }
        if(clientID !== undefined){
            if(clientID !== gotCaptcha.client_id){
                return false;
            }
        }
        if(user_uid !== undefined){
            if(user_uid !== gotCaptcha.uid){
                return false;
            }
        }
        if(mask_uid !== undefined){
            if(mask_uid !== gotCaptcha.mask_uid){
                return false;
            }
        }
        if(this.backendCaptchaSystemSetting.needMatchIPAddr){
            let originalAddr = parseIPAddr(gotCaptcha.ip_address);
            let newAddr = parseIPAddr(ipAddress);
            if(originalAddr !== undefined && newAddr !== undefined){
                if(originalAddr.bigInteger() !== newAddr.bigInteger()){
                    return false;
                }
            }
        }
        return gotCaptcha.captcha_ans === verifyInfo.captcha_ans;
    }
    async verifyAndUseCaptcha(verifyInfo: SimpleCaptchaVerifyInfo, ipAddress: string, clientID?: string | null, user_uid?: UserEntityUID, mask_uid?: MaskUID): Promise<boolean> {
        let checkResult = await this.verifyCaptcha(verifyInfo,ipAddress,clientID,user_uid,mask_uid);
        if(checkResult){
            await this.storageEngine.useCaptcha(verifyInfo.captcha_id);
        }
        return checkResult;
    }
    async parseCaptchaVerifyInfo(toParse: any): Promise<SimpleCaptchaVerifyInfo | undefined> {
        if(typeof(toParse) !== 'object'){
            return undefined;
        }
        
        if(!('captcha_id' in toParse) || typeof(toParse.captcha_id) !== 'string' || toParse.captcha_id === ''){
            return undefined;
        }
        if(!('captcha_ans' in toParse) || typeof(toParse.captcha_ans) !== 'string' || toParse.captcha_ans === ''){
            return undefined;
        }
        return {
            captcha_id: toParse.captcha_id,
            captcha_ans: toParse.captcha_ans
        };
    }
    async parseCaptchaCreateInfo(toParse: any): Promise<SimpleCaptchaCreateInfo | undefined> {
        if(typeof(toParse) !== 'object' || !('isDarkMode' in toParse)){
            return {};
        }
        if(typeof(toParse.isDarkMode) === 'boolean'){
            return {
                isDarkMode: toParse.isDarkMode
            };
        }else{
            return {isDarkMode: toParse.isDarkMode == true};
        }
    }
    clearOutdatedAndUsedCaptchas(): Promise<void> {
        return this.storageEngine.clearOutdatedAndUsedCaptchas();
    }
    install(params: CaptchaFactoryInstallInfo): Promise<void> {
        return this.storageEngine.install(params,this.getCaptchaIDLen(),this.getCaptchaAnsLen());
    }
    uninstall(): Promise<void> {
        return this.storageEngine.uninstall();
    }
    clearData(): Promise<void> {
        return this.storageEngine.clearData();
    }
}

export {SimpleCaptchaFactory};