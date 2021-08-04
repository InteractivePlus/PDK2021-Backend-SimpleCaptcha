import IpAddress from 'ip-address';
function parseIPAddr(ip: string) : IpAddress.Address4 | IpAddress.Address6 | undefined{ 
    try{
        if(IpAddress.Address4.isValid(ip)){
            return new IpAddress.Address4(ip);
        }else if(IpAddress.Address6.isValid(ip)){
            return new IpAddress.Address6(ip);
        }else{
            return undefined;
        }
    }catch(err){
        return undefined;
    }
}
export {parseIPAddr};