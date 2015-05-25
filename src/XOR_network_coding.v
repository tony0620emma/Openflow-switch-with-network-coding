///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: opl_processor.v 5988 2010-03-09 07:04:41Z tyabe $
//
// Module: opl_processor.v
// Project: NF2.1 OpenFlow Switch
// Author: Jad Naous <jnaous@stanford.edu>
//         Tatsuya Yabe <tyabe@stanford.edu>
// Description: Appends the actions to take on a packet to the beginning of
// a packet then pushes the packet out to the next module.
// This module performs all the modify actions supported on OpenFlow v1.0,
// with checksum recalculation.
//
// Licensing: In addition to the NetFPGA license, the following license applies
//            to the source code in the OpenFlow Switch implementation on NetFPGA.
//
// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
//
// We are making the OpenFlow specification and associated documentation (Software)
// available for public use and benefit with the expectation that others will use,
// modify and enhance the Software and contribute those enhancements back to the
// community. However, since we would like to make the Software available for
// broadest use, with as few restrictions as possible permission is hereby granted,
// free of charge, to any person obtaining a copy of this Software to deal in the
// Software under the copyrights without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// The name and trademarks of copyright holder(s) may NOT be used in advertising
// or publicity pertaining to the Software or any derivatives without specific,
// written prior permission.
///////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps

module 
  #(parameter NUM_OUTPUT_QUEUES = 8,
    parameter DATA_WIDTH = 64,
    parameter CTRL_WIDTH = DATA_WIDTH/8)
  (// --- interface to opl_processor
   input [DATA_WIDTH-1:0]                  in_data,
   input [CTRL_WIDTH-1:0]                  in_ctrl,
   input                                   in_wr,
  
   // --- interface to output
   output reg [DATA_WIDTH-1:0]             out_data,
   output reg [CTRL_WIDTH-1:0]             out_ctrl,
   output reg                              out_wr,
   input                                   out_rdy,
   
   // --- Misc
   input                                   clk,
   input                                   reset);
   
   //-------------------- Internal Parameters ------------------------
   localparam WAIT_FOR_INPUT_0 = 0 ,
			  
   
   //-------------------- Wires and regs ------------------------
   
   //-------------------- modules ----------------------------------------------------------
   
   fallthrough_small_fifo #(.WIDTH(CTRL_WIDTH+DATA_WIDTH), .MAX_DEPTH_BITS(7))
     packet_fifo_0
       (.din           ({in_ctrl, in_data}),  // Data in
        .wr_en         (in_wr_0),             // Write enable
        .rd_en         (packet_fifo_0_rd_en),    // Read the next word
        .dout          ({packet_fifo_0_ctrl, packet_fifo_0_data}),
        .prog_full     (),
        .full          (),
        .nearly_full   (packet_fifo_0_nearly_full),
        .empty         (packet_fifo_0_empty),
        .reset         (reset),
        .clk           (clk)
        );
   
   fallthrough_small_fifo #(.WIDTH(CTRL_WIDTH+DATA_WIDTH), .MAX_DEPTH_BITS(2))
     packet_fifo_1
       (.din           ({in_ctrl, in_data}),  // Data in
        .wr_en         (in_wr_1),             // Write enable
        .rd_en         (packet_fifo_1_rd_en),    // Read the next word
        .dout          ({packet_fifo_1_ctrl, packet_fifo_1_data}),
        .prog_full     (),
        .full          (),
        .nearly_full   (packet_fifo_1_nearly_full),
        .empty         (packet_fifo_1_empty),
        .reset         (reset),
        .clk           (clk)
        );
   
   
   
   
   
   
   
   
   
   
   
   
   
endmodule // XOR_network_coding
