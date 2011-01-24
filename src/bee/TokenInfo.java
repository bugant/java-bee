/*
 *   Copyright (c) 2010 Matteo Centenaro
 *   
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

package bee;
public class TokenInfo
{
    private String label;
    private String model;
    private String manufacturer;
    private String serial;
    private String hwdVersion;
    private String firmVersion;

    public static final int LABEL = 0;
    public static final int MODEL = 1;
    public static final int MANUFACTURER = 2;
    public static final int SERIAL = 3;
    public static final int HWD_VERSION = 4;
    public static final int FIRM_VERSION = 5;

    public TokenInfo(String label, String model, String manufacturer, String serial, String hwdVersion, String firmVersion)
    {
        this.label = label;
        this.model = model;
        this.manufacturer = manufacturer;
        this.serial = serial;
        this.hwdVersion = hwdVersion;
        this.firmVersion = firmVersion;
    }

    public String getLabel() {return this.label;}

    public String getModel() {return this.model;}

    public String getManufacturer() {return this.manufacturer;}

    public String getSerial() {return this.serial;}

    public String getHardwareVersion() {return this.hwdVersion;}

    public String getFirmwareVersion() {return this.firmVersion;}

    public String toString()
    {
        return "Label: " + this.getLabel() + "\nModel: " + this.getModel() +
            "\nManufacturer: " + this.getManufacturer() + "\nSerial #: " + this.getSerial() +
            "\nHardware version: " + this.getHardwareVersion() + "\nFirmware version: " + this.getFirmwareVersion();
    }
}
