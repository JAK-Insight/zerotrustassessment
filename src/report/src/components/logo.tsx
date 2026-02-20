import { ztAppConfig } from "@/config/app";
import { Icons } from "./icons";
import insightLogo from "@/assets/insight-logo.png";

export function Logo() {
    return (
        <>
            <img src={insightLogo} alt="Insight" className="h-6 w-auto mr-2" />
            <Icons.logo className="h-6 w-6" />
            <span className="font-bold">{ztAppConfig.name}</span>
        </>
    )
}
