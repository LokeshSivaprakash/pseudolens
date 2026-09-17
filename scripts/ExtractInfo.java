import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;

public class ExtractInfo extends GhidraScript {
    private static final int MAX_DECOMPILE = 15;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/work/output/report.json";

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        StringBuilder functionsJson = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        int decompiledCount = 0;
        int totalFunctions = 0;
        for (Function func : funcMgr.getFunctions(true)) {
            totalFunctions++;
            if (count >= 50) continue;
            if (!first) functionsJson.append(",");

            String decompiledCode = "";
            if (decompiledCount < MAX_DECOMPILE) {
                DecompileResults results = decompiler.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (results != null && results.decompileCompleted()) {
                    decompiledCode = results.getDecompiledFunction().getC();
                }
                decompiledCount++;
            }

            functionsJson.append("{\"name\":\"").append(escape(func.getName()))
                .append("\",\"entry\":\"").append(func.getEntryPoint().toString())
                .append("\",\"decompiled\":\"").append(escape(decompiledCode)).append("\"}");
            first = false;
            count++;
        }
        functionsJson.append("]");
        decompiler.dispose();

        ExternalManager extMgr = currentProgram.getExternalManager();
        StringBuilder importsJson = new StringBuilder("[");
        boolean firstImp = true;
        for (String lib : extMgr.getExternalLibraryNames()) {
            if (!firstImp) importsJson.append(",");
            importsJson.append("\"").append(escape(lib)).append("\"");
            firstImp = false;
        }
        importsJson.append("]");

        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        StringBuilder stringsJson = new StringBuilder("[");
        boolean firstStr = true;
        int strCount = 0;
        while (dataIter.hasNext() && strCount < 200) {
            Data d = dataIter.next();
            if (d.hasStringValue()) {
                if (!firstStr) stringsJson.append(",");
                stringsJson.append("\"").append(escape(d.getValue().toString())).append("\"");
                firstStr = false;
                strCount++;
            }
        }
        stringsJson.append("]");

        String json = "{\"functions_found\":" + totalFunctions +
            ",\"functions\":" + functionsJson.toString() +
            ",\"imported_libraries\":" + importsJson.toString() +
            ",\"strings_sample\":" + stringsJson.toString() + "}";

        FileWriter writer = new FileWriter(outPath);
        writer.write(json);
        writer.close();
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
