/*
 * Licensed under the Open Software License version 3.0
 */

package noconnect;

import net.minecraftforge.fml.ExtensionPoint;
import net.minecraftforge.fml.ModLoadingContext;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.network.FMLNetworkConstants;
import org.apache.commons.lang3.tuple.Pair;

@Mod("noconnect")
public class NoConnect {

    public NoConnect() {
        // Make sure the mod being absent on the other network side
        // does not cause the client to display the server as incompatible.
        ModLoadingContext.get().registerExtensionPoint(ExtensionPoint.DISPLAYTEST,
                () -> Pair.of(() -> FMLNetworkConstants.IGNORESERVERONLY, (a, b) -> true));
    }

}
