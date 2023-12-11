#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include<string.h>
#include <map>
#include <set>
#include <vector>
#include <stack>
#include <queue>
#include <list>

using namespace std;

/*This enum values are realted to protocols */
enum protocol
{
	NONE = 0,
	ETHERNET,
	IPV4,
	IPV6,
	TCP,
	UDP
};


vector<int> protocol_accessed(5,0);  /*To handle the query: Which snippet is dropping TCP packet, we need to use this vector.
If protocol_check is 1 but the protocol is not accessed that means the protocol will be dropped
0: ethernet, 1: IPV4, 2: IPV6, 3: TCP, 4: UDP */
vector<int> protocol_check(4) ;  // 0 : IPv4, 1 : IPv6, 2 : TCP, 3 : UDP 

int current_protocol = NONE;   //This variable contains the value of the current protocol 

stack<int> stack_protocol;  // As soon as we get the protocol confirmation on the if statements, we push it into the stack

/* This function prints all the protocols that have been used in a particular path. Here, we have made use the stack_protocol stack into this*/
void print_protocol()
{
	if(stack_protocol.empty())
	{
		cout<<"No Protocol"<<endl;
	}
	else
	{
		while(!stack_protocol.empty())
		{
			int proto = stack_protocol.top();
			switch (proto) 
			{
				case 1 :
				{
					cout<<"Ethernet accessed"<<endl;
					break;
				}
				case 2 :
				{
					cout<<"IPV4 accessed"<<endl;
					break;
				}
				case 3 :
				{
					cout<<"IPV6 accessed"<<endl;
					break;
				}
				case 4 :
				{
					cout<<"TCP accessed"<<endl;
					break;
				}
				case 5 :
				{
					cout<<"UDP accessed"<<endl;
					break;
				}
				default :
				{
					cout<<"UNKNOWN Protocol accessed"<<endl;
				}

			}
			stack_protocol.pop();

			
		}
	}

}


/* This struct contains the type of value that the register contains in the "Tag" field and the value that it conatains  */
struct reg_state
{
	int tag;
	int value;
};

/* This vector is used to verify if the protocol is actually accessed or not */
vector<reg_state> state_array(11);

/* These are the enum values which the "Tag" field will contain for each register */
enum reg_tag{
	garbage_value = 0,    //If the tag of the register is garbage_value then the value will be having garbage value.
	integer ,             //If the tag is integer and if the value is 0, that will be integer 0
	ptr_to_ctx  ,
	ptr_to_packet_start ,
	ptr_to_packet_end ,
	ptr_to_frame ,
	some_protocol_field,
	eth_proto,
	ip_proto,
	ipv6_proto
 /* The reason for tracking only the protocol fields: Since we were only tracking the protocols accessed as per the 1st Query,
 so for checking the next protocol we had only tracked the protocol fields of all the possible headers as the value of the next header is 
 stored in these fields only */
	
};

/* After one path have been executed, we need re-initialize the array which stores the tag and value of each registers. This work is done by this function*/
void re_initialize_state_array()
{
	state_array[0].tag = integer;
    state_array[0].value = garbage_value;
    state_array[10].tag = ptr_to_frame;
    state_array[10].value = garbage_value;
    state_array[1].tag = ptr_to_ctx;
	state_array[1].value = garbage_value;
	for(int i = 2 ; i<10 ; i++)
	{
		state_array[i].tag = garbage_value;
		state_array[i].value = garbage_value;
	}
}

vector<vector<int>> all_paths;  //This vector contains all the possible paths in the a code


/* This function is used to print the states of all the registers after a path have been executed */
void print_reg_state(int it){
	cout<<"Register states after "<<it<<"th path "<<endl;
	for(int i = 0 ; i<11 ; i++){
		cout<<"Register "<<i<<" tag :"<<state_array[i].tag<<" Value : "<<state_array[i].value<<endl;
	}
	re_initialize_state_array();
}

/* This function is used to return the helper function used. This function takes the immediate value from the call instruction and gives the helper function used */
string get_helper_name(int id){
	map<int, string> helper_id_name;

	//Helper function database
	helper_id_name = {{0,"unspec"},{1,"map_lookup_elem"},{2,"map_update_elem"},{3,"map_delete_elem"},{4,"probe_read"},{5,"ktime_get_ns"},{6,"trace_printk"},{7,"get_prandom_u32"},{8,"get_smp_processor_id"},{9,"skb_store_bytes"},{10,"l3_csum_replace"},
					{11,"l4_csum_replace"},{12,"tail_call"},{13,"clone_redirect"},{14,"get_current_pid_tgid"},{15,"get_current_uid_gid"},{16,"get_current_comm"},{17,"get_cgroup_classid"},{18,"skb_vlan_push"},{19,"skb_vlan_pop"},{20,"skb_get_tunnel_key"},
					{21,"skb_set_tunnel_key"},{22,"perf_event_read"},{23,"redirect"},{24,"get_route_realm"},{25,"perf_event_output"},{26,"skb_load_bytes"},{27,"get_stackid"},{28,"csum_diff"},{29,"skb_get_tunnel_opt"},{30,"skb_set_tunnel_opt"},{31,"skb_change_proto"},
					{32,"skb_change_type"},{33,"skb_under_cgroup"},{34,"get_hash_recalc"},{35,"get_current_task"},{36,"probe_write_user"},{37,"current_task_under_cgroup"},{38,"skb_change_tail"},{39,"skb_pull_data"},{40,"csum_update"},{41,"set_hash_invalid"},{42,"get_numa_node_id"},
					{43,"skb_change_head"},{44,"xdp_adjust_head"},{45,"probe_read_str"},{46,"get_socket_cookie"},{47,"get_socket_uid"},{48,"set_hash"},{49,"setsockopt"},{50,"skb_adjust_room"},{51,"redirect_map"},{52,"sk_redirect_map"},{53,"sock_map_update"},{54,"xdp_adjust_meta"},
					{55,"perf_event_read_value"},{56,"perf_prog_read_value"},{57,"getsockopt"},{58,"override_return"},{59,"sock_ops_cb_flags_set"},{60,"msg_redirect_map"},{61,"msg_apply_bytes"},{62,"msg_cork_bytes"},{63,"msg_pull_data"},{64,"bind"},{65,"xdp_adjust_tail"},
					{66,"skb_get_xfrm_state"},{67,"get_stack"},{68,"skb_load_bytes_relative"},{69,"fib_lookup"},{70,"sock_hash_update"},{71,"msg_redirect_hash"},{72,"sk_redirect_hash"},{73,"lwt_push_encap"},{74,"lwt_seg6_store_bytes"},{75,"lwt_seg6_adjust_srh"},{76,"lwt_seg6_action"},
					{77,"rc_repeat"},{78,"rc_keydown"},{79,"skb_cgroup_id"},{80,"get_current_cgroup_id"},{81,"get_local_storage"},{82,"sk_select_reuseport"},{83,"skb_ancestor_cgroup_id"},{84,"sk_lookup_tcp"},{85,"sk_lookup_udp"},{86,"sk_release"},{87,"map_push_elem"},{88,"map_pop_elem"},
					{89,"map_peek_elem"},{90,"msg_push_data"},{91,"msg_pop_data"},{92,"rc_pointer_rel"},{93,"spin_lock"},{94,"spin_unlock"},{95,"sk_fullsock"},{96,"tcp_sock"},{97,"skb_ecn_set_ce"},{98,"get_listener_sock"},{99,"skc_lookup_tcp"},{100,"tcp_check_syncookie"},
					{101,"sysctl_get_name"},{102,"sysctl_get_current_value"},{103,"sysctl_get_new_value"},{104,"sysctl_set_new_value"},{105,"strtol"},{106,"strtoul"},{107,"sk_storage_get"},{108,"sk_storage_delete"},{109,"send_signal"},{110,"tcp_gen_syncookie"},{111,"skb_output"},
					{112,"probe_read_user"},{113,"probe_read_kernel"},{114,"probe_read_user_str"},{115,"probe_read_kernel_str"},{116,"tcp_send_ack"},{117,"send_signal_thread"},{118,"jiffies64"},{119,"read_branch_records"},{120,"get_ns_current_pid_tgid"},{121,"xdp_output"},
					{122,"get_netns_cookie"},{123,"get_current_ancestor_cgroup_id"},{124,"sk_assign"},{125,"ktime_get_boot_ns"},{126,"seq_printf"},{127,"seq_write"},{128,"sk_cgroup_id"},{129,"sk_ancestor_cgroup_id"},{130,"ringbuf_output"},{131,"ringbuf_reserve"},{132,"ringbuf_submit"},
					{133,"ringbuf_discard"},{134,"ringbuf_query"},{135,"csum_level"},{136,"skc_to_tcp6_sock"},{137,"skc_to_tcp_sock"},{138,"skc_to_tcp_timewait_sock"},{139,"skc_to_tcp_request_sock"},{140,"skc_to_udp6_sock"},{141,"get_task_stack"},{142,"load_hdr_opt"},{143,"store_hdr_opt"},
					{144,"reserve_hdr_opt"},{145,"inode_storage_get"},{146,"inode_storage_delete"},{147,"d_path"},{148,"copy_from_user"},{149,"snprintf_btf"},{150,"seq_printf_btf"},{151,"skb_cgroup_classid"},{152,"redirect_neigh"},{153,"per_cpu_ptr"},{154,"this_cpu_ptr"},{155,"redirect_peer"},
					{156,"task_storage_get"},{157,"task_storage_delete"},{158,"get_current_task_btf"},{159,"bprm_opts_set"},{160,"ktime_get_coarse_ns"},{161,"ima_inode_hash"},{162,"sock_from_file"},{163,"check_mtu"},{164,"for_each_map_elem"},{165,"snprintf"},{166,"sys_bpf"},{167,"btf_find_by_name_kind"},
					{168,"sys_close"},{169,"timer_init"},{170,"timer_set_callback"},{171,"timer_start"},{172,"timer_cancel"},{173,"get_func_ip"},{174,"get_attach_cookie"},{175,"task_pt_regs"},{176,"get_branch_snapshot"},{177,"trace_vprintk"},{178,"skc_to_unix_sock"},{179,"kallsyms_lookup_name"},{180,"find_vma"},
					{181,"loop"},{182,"strncmp"},{183,"get_func_arg"},{184,"get_func_ret"},{185,"get_func_arg_cnt"},{186,"get_retval"},{187,"set_retval"},{188,"xdp_get_buff_len"},{189,"xdp_load_bytes"},{190,"xdp_store_bytes"},{191,"copy_from_user_task"},{192,"skb_set_tstamp"},{193,"ima_file_hash"},
					{194,"kptr_xchg"},{195,"map_lookup_percpu_elem"},{196,"skc_to_mptcp_sock"},{197,"dynptr_from_mem"},{198,"ringbuf_reserve_dynptr"},{199,"ringbuf_submit_dynptr"},{200,"ringbuf_discard_dynptr"},{201,"dynptr_read"},{202,"dynptr_write"},{203,"dynptr_data"},{204,"tcp_raw_gen_syncookie_ipv4"},
					{205,"tcp_raw_gen_syncookie_ipv6"},{206,"tcp_raw_check_syncookie_ipv4"},{207,"tcp_raw_check_syncookie_ipv6"},{208,"ktime_get_tai_ns"},{209,"user_ringbuf_drain"},{210,"cgrp_storage_get"},{211,"cgrp_storage_delete"},};

	return helper_id_name[id];
}

class parse_inst{
	public:		
		// struct inst{
		// 	__u8	code;		/* opcode */
		// 	__u8	dst_reg:4;	/* dest register */
		// 	__u8	src_reg:4;	/* source register */
		// 	__s16	off;		/* signed offset */
		// 	__s32	imm;
		// };	/* signed immediate constant */
		/*Taken from linux/bpf.h*/
		
		struct reg_state // Redundant struct
		{
			int tag;
			int value;
		};

		struct bpf_object *obj;
		struct bpf_program *bpf_prog;
		const struct bpf_insn *orig_insns;
		vector<bpf_insn> inst_list;
		size_t inst_count;
		vector<reg_state> state_array[11]; 	//This vector will hold the tag and value of all the 11 registers  
	

		//Getters
		size_t get_inst_cout(){
			return inst_count;
		}

		vector<bpf_insn> get_inst_list(){
			return inst_list;
		}

		bpf_object *get_bpf_object(){
			return obj;
		}
		parse_inst(const char *filename, const char *prog_name);

};	

parse_inst :: parse_inst(const char *filename, const char *prog_name){
			obj = bpf_object__open_file(filename, NULL);
			if (libbpf_get_error(obj)) {
				cout << stderr, "ERROR: opening BPF object file failed\n";
				// return 0;
				exit;
			}

			bpf_prog = bpf_object__find_program_by_name(obj, prog_name);
			if (!bpf_prog) {
				cout << "finding a prog in obj file failed\n";
				// return 0 ; 
				exit;
			}
			orig_insns = bpf_program__insns(bpf_prog);
			inst_count = bpf_program__insn_cnt(bpf_prog);
			cout<<inst_count;
			for(int i=0; i < inst_count ; i++){
				inst_list.push_back(bpf_insn()) ;
				inst_list[i].code = (orig_insns+i)->code ; 
				inst_list[i].dst_reg = (orig_insns+i)->dst_reg ; 
				inst_list[i].src_reg = (orig_insns+i)->src_reg ; 
				inst_list[i].off = (orig_insns+i)->off ; 
				inst_list[i].imm = (orig_insns+i)->imm ; 
			}
		}


/* This graph is responsible for giving all the paths present in the a code based on the "If statements" */
class CFGraph {  
public:
    int vertex_cnt; // Instruction count
    list<int>* adj; // Pointer to an array containing
                    // adjacency lists represeantation
	
	vector<int> single_path;
 
    // A recursive function used by get_all_paths()
    void dfs(int src_ind, int dst_ind, bool visited[], int path[], int& path_index){
		// Mark the current node and store it in path[]
		visited[src_ind] = true;
		path[path_index] = src_ind;
		path_index++;
	
		// If current vertex is same as destination, then print
		// current path[]
		if (src_ind == dst_ind) {
			for (int i = 0; i < path_index; i++){
				//cout << path[i] << " ";
				single_path.push_back(path[i]);
			}
			all_paths.push_back(single_path);
			single_path.clear();
		}
		else // If current vertex is not destination
		{
			// For all the vertices adjacent to current vertex do Recursion
			list<int>::iterator i;
			for (i = adj[src_ind].begin(); i != adj[src_ind].end(); ++i)
				if (!visited[*i]){
					dfs(*i, dst_ind, visited, path,
									path_index);
					// cout << "single_path.size(): "<<single_path.size();
				}
		}
	
		// Remove current vertex from path[] and mark it as unvisited
		path_index--;
		visited[src_ind] = false;
	}
	
	CFGraph(int vertex_cnt);
	void addEdge(int src, int dst){
		adj[src].push_back(dst); // Add v to u’s list.
	}

	vector<vector<int>> get_all_paths(int s, int d) // This function will list down all the paths present between a source node and dest node. In our case the source node will be 1st instruction and the dest node will be the "Exit node"
	{
		// Mark all the vertices as not visited
		bool* visited = new bool[vertex_cnt];
	
		// Create an array to store paths
		int* path = new int[vertex_cnt];
		int path_index = 0; // Initialize path[] as empty
	
		// Initialize all vertices as not visited
		for (int i = 0; i < vertex_cnt; i++)
			visited[i] = false;
	
		// Call the recursive helper function to print all paths
		dfs(s, d, visited, path, path_index);
		return all_paths;
	}	
};

CFGraph :: CFGraph(int vertex_cnt){
	this->vertex_cnt = vertex_cnt;
	adj = new list<int>[vertex_cnt];
	//cout << "\nINST CNT: "<<vertex_cnt;

}

/* This struct holds the data for each of the edge */
struct edge{
	int src;
	int dst;
};


class flow_prop {
		
				
	public:

		/* This function handles the instruction of JMP class  */
		void parse_JMP(int mode, char src_reg[20], char dst_reg[20], int imm, int it ,int itx, int off)
		{
			int local_src_reg = find_reg(src_reg);
			int local_dst_reg = find_reg(dst_reg);
			int next_inst = all_paths[it][itx+1];
			int curr_inst = all_paths[it][itx];
			if(mode == BPF_LEN ){
				cout<<"This is an exit instruction"<<endl;
			}
			else if(mode == BPF_ABS ){
				cout<<"IF stmt : Mostly for Sanity check "<<endl;
				
			    
				if(curr_inst + off + 1 == next_inst){
					cout<<"Protocol : Check failed for this IF stmt "<<endl;
				}
				
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 14){
					cout<<"Protocol : Ethernet"<<endl;
					current_protocol = ETHERNET;
					stack_protocol.push(current_protocol);
					protocol_accessed[0] = 1;
				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 34 && protocol_check[0] == 1)
				{
					cout<<"Protocol : IPV4"<<endl;
					current_protocol = IPV4;
					stack_protocol.push(current_protocol);
					protocol_accessed[1] = 1;

				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 54 && protocol_check[2] == 1 )
				{
					cout<<"Protocol : TCP"<<endl;
					current_protocol = TCP;
					stack_protocol.push(current_protocol);
					protocol_accessed[3] = 1;

				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 42 && protocol_check[3] == 1)
				{
					cout<<"Protocol : UDP"<<endl;
					current_protocol = UDP;
					stack_protocol.push(current_protocol);
					protocol_accessed[4] = 1;
				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 54 && protocol_check[1] == 1)
				{
					cout<<"Protocol : IPV6"<<endl;
					current_protocol = IPV6;
					stack_protocol.push(current_protocol);
					protocol_accessed[2] = 1;
				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 74 && protocol_check[2] == 1)
				{
					cout<<"Protocol : TCP"<<endl;
					current_protocol = TCP;
					stack_protocol.push(current_protocol);
					protocol_accessed[3] = 1;
				}
				else if(state_array[local_src_reg].tag == ptr_to_packet_end && state_array[local_dst_reg].tag == ptr_to_packet_start && state_array[local_dst_reg].value == 62 && protocol_check[3] == 1)
				{
					cout<<"Protocol : UDP"<<endl;
					current_protocol = UDP;
					stack_protocol.push(current_protocol);
					protocol_accessed[4] = 1;
				}
				else
				{
					cout<<"Can't figure out this statement"<<endl;
				}
			}
			else if(mode == BPF_IND){
				cout<<"This is IF stmt : < != > "<<endl;
				
				if((state_array[local_dst_reg].tag == eth_proto) && (imm == 2048 || imm == 8))
				{
				/*Note that Protocol value of IPV4 is 0x0800. Based on the endianness, that value for checking for IPV4 can be 2048(Which is equivalent to 0x0800) 
					or 8(which is equivalent to 0x0008) */
					if(next_inst == curr_inst + 1){
						cout<<"IPV4 Maybe accessed"<<endl;
						protocol_check[0] = 1;

					}
					else{
						cout<<"Check for IP failed"<<endl;
					}
				}	
				else if((state_array[local_dst_reg].tag == eth_proto) && ((imm == 34525) || (imm == 56710))){
					/*Note that Protocol value of IPV6 is 0x86DD. Based on the endianness, that value for checking for IPV6 can be 34525(Which is equivalent to 0x86DD) 
					or 56710(which is equivalent to 0xDD86) */
					if(next_inst == curr_inst + 1){
						cout<<"IPV6 Maybe accessed"<<endl;
						protocol_check[1] = 1;

					}
					else{
						cout<<"Check for IPV6 failed"<<endl;
					}
				}	

				else if(((state_array[local_dst_reg].tag == ip_proto) || (state_array[local_dst_reg].tag == ipv6_proto)) && (imm == 6)){
					if(next_inst == curr_inst + 1){
						cout<<"TCP maybe accessed"<<endl;
						protocol_check[2] = 1;
					}
					else{
						cout<<"Check for TCP failed"<<endl;
					}
				}
				else if(((state_array[local_dst_reg].tag == ip_proto)|| (state_array[local_dst_reg].tag == ipv6_proto)) && (imm == 17)){
					if(next_inst == curr_inst + 1){
						cout<<"UDP maybe accessed"<<endl;
						protocol_check[3] = 1;
					}
					else{
						cout<<"Check for UDP failed"<<endl;
					}
				}
				else if((state_array[local_dst_reg].tag == ipv6_proto) && (imm == 34525)){
					/*This is a false condition as this can't happen any time*/
					if(next_inst == curr_inst + 1)
					{
					 cout<<"IPV6 maybe accessed"<<endl;
					 protocol_check[1] = 1;
					}
					else
					{
						cout<<"Check for IPV6 failed"<<endl;
					}


				}
				else
				{
					if(next_inst == curr_inst + 1)
					{
					   cout<<"This IF stmt failed"<<endl;

					}
					else
					{
						cout<<"This IF stmt was TRUE"<<endl;
					}
					
				}
			}
			else if(mode == BPF_IMM){
				/*Logic yet to be written*/
				cout<<"This is IF stmt : < == > "<<endl;
				if(next_inst == curr_inst + off  + 1)
				{
					if(((state_array[local_dst_reg].tag == ip_proto) || (state_array[local_dst_reg].tag == ipv6_proto)) && (imm == 6))
					{
						cout<<"TCP maybe accessed"<<endl;
						protocol_check[2] = 1;

					}
					else if(((state_array[local_dst_reg].tag == ip_proto) || (state_array[local_dst_reg].tag == ipv6_proto)) && (imm == 17))
					{
						cout<<"UDP maybe accessed"<<endl;
						protocol_check[3] = 1;
					}
					else if(state_array[local_dst_reg].tag == some_protocol_field)
					{
						cout<<"Some Successful comparison has been done"<<endl;
					}
					else if((state_array[local_dst_reg].tag == eth_proto) && ((imm == 34525)||(imm == 56710 )))
					{
						cout<<"IPV6 may be accessed"<<endl;
						protocol_check[1] = 1;
					}
					else if((state_array[local_dst_reg].tag == eth_proto) && ((imm == 2048) || (imm == 8)))
					{
						cout<<"IPV4 may be accessed"<<endl;
						protocol_check[0] = 1;
					}
					

				}
				else{
						cout<<"This IF check of < == > was FAILED"<<endl;
					}
			}
		}

		/* As the registers are in char format, and we wanted the integer associated to the register, so we use this function*/
		int find_reg(char reg[20]){
			int n_reg = atoi(reg);
			//BPF_REG_0

			if(reg[0] == 'A'){   // If the register is r10, then we handle this case
				cout << "\nAAAAA";
				return 10;	
			}
			return n_reg;
		}


		/* This function is used to handle the "MISC" instruction */
		void parse_MISC(int mode, char src_reg[20], char dst_reg[20], int imm){
			int local_src_reg = find_reg(src_reg);
			int local_dst_reg = find_reg(dst_reg);
			if(mode == BPF_MSH)
			{
				
				if(local_src_reg == 0){
				
				cout<<"Register is : "<<local_dst_reg<<endl;
				state_array[local_dst_reg].value =imm;
				state_array[local_dst_reg].tag = integer;
				cout<<"Tag : "<<state_array[local_dst_reg].tag <<" Value : "<<state_array[local_dst_reg].value<<endl;

				}
				else if(local_src_reg != 0)
				{
					state_array[local_dst_reg].tag = state_array[local_src_reg].tag;
					state_array[local_dst_reg].value = state_array[local_src_reg].value;
					cout<<"Value and tag of reg R"<<local_src_reg<<" copied to R"<<local_dst_reg<<endl;

				}     
				
			}
			else if (mode == BPF_IMM)
			{
				state_array[local_dst_reg].value += imm;
				cout<<"Value of R"<<local_dst_reg<<" incr by "<<imm<<endl;
			}
			else
			{
				cout<<"No Action taken"<<endl;
			}
		}

		/* This function is used to handle "LDX" instructions */
		void parse_LDX(char dst_reg[20], char src_reg[20], int size, int off, int imm, int mode)
		{
			int local_src_reg = find_reg(src_reg);
			int local_dst_reg = find_reg(dst_reg);
			// cout << "\n####: " << local_src_reg << "\n";
			// cout << "\n####: " <<state_array[local_src_reg].tag << "\n";
			// cout << "\n####: " <<size << "\n";
		
		if((state_array[local_src_reg].tag == ptr_to_ctx) && (size == BPF_W) && (off == 4 ))
			{
				state_array[local_dst_reg].tag = ptr_to_packet_end;
				cout<<"This is packet end \n" <<src_reg <<endl;
				// cout << "\n####" <<src_reg ;

			}
			else if((state_array[local_src_reg].tag == ptr_to_ctx) && (size == BPF_W) && (off == 0 ))
			{
				state_array[local_dst_reg].tag = ptr_to_packet_start;
				cout<<"This is packet start"<<endl;
				// cout << "\n####" <<src_reg ;

			}
			else if((state_array[local_src_reg].tag == ptr_to_packet_start) && (size == BPF_B) && (off == 12 || off == 13) && (current_protocol == ETHERNET))
			{
				state_array[local_dst_reg].tag = eth_proto;
				cout<<"eth_proto was accessed"<<endl;
				// cout << "\n####" <<src_reg ;
			}
			else if ((state_array[local_src_reg].tag == ptr_to_packet_start) && (size == BPF_B) && (off == 23) && (current_protocol == IPV4))
			{
				state_array[local_dst_reg].tag = ip_proto;
				cout<<"ip_proto was accessed"<<endl;
				// cout << "\n####" <<src_reg ;
			}
			else if((state_array[local_src_reg].tag == ptr_to_packet_start) && (size == BPF_B) && (off == 20) && (current_protocol == IPV6))
			{
				state_array[local_dst_reg].tag = ipv6_proto;
				cout<<"ipv6_proto was accessed"<<endl;
				cout<<"\n";

			}
			else if(state_array[local_src_reg].tag == ptr_to_packet_start)
			{
				int some_field = stack_protocol.top();
				cout<<"Some Field is being accessed of Protocol : "<<some_field<<endl;
				state_array[local_dst_reg].tag = some_protocol_field;

			}
		 
		}

		/* This function is used to handle the "ALU" instruction */
		void parse_ALU(char src_reg[20], char dst_reg[20], int mode)
		{
			int local_dst_reg = find_reg(dst_reg);
			if(mode == 192)
			{
				cout<<"Just changed representation of the value present in R"<<local_dst_reg<<endl;
			}
		}

		/* This function has the logic based on which we take decisions and update the states of the registers. 
		Based on the class and mode/code for each instruction we call the corresponding function, and that function uses the information
		passed as the arguments,processes it, takes decision and updates the register's states */
		void parse_linebyline(char src_reg[20], char dst_reg[20], int mode,int ins_class,int imm,int off,int size, int it, int itx){
			if(ins_class == BPF_JMP){
				cout<<"Entered hex_class = 5"<<endl;
				parse_JMP(mode, src_reg, dst_reg, imm, it ,itx, off);
			}

			else if(ins_class == BPF_MISC){
				cout<<"Entered hex_class = 7"<<endl;
				parse_MISC(mode, src_reg, dst_reg, imm);
				/*Storing value, addition, subtraction*/
			}
			else if(ins_class == BPF_LDX){
				cout<<"Entered BPF_LDX class"<<endl;
				parse_LDX(dst_reg,src_reg,size, off, imm, mode);
			}
			else if(ins_class == BPF_ALU){
				cout<<"Entered BPF_ALU class"<<endl;
				parse_ALU(src_reg,dst_reg,mode);
			}
			else{
				cout<<"Non Matching class"<<endl;
			}   

		}

		/* This function is used to get relevant information from the hexadecimal part of the bytecode, 
		like source/dest register, code/mode, class, size, immediate value, offset value */
		void get_information(parse_inst p1, int it){
            cout<<"Number of Instructions : " << p1.inst_count<<endl;
            cout<<"Size of the path is : "<<all_paths[it].size()<<endl;
			//cout<<"Number of Instructions : " << p1.inst_count<<endl;
			/*Here we can put an array that will be traversed*/
			for(int itx=0 ; itx < all_paths[it].size() ; itx++)
			{
                int i = all_paths[it][itx];
				char hex_src_reg[20], hex_dst_reg[20],hex_code[20], hex_mode[20], hex_class[20], hex_size[20], hex_imm[20], hex_off[20];
				//int src_reg ;
				//int dst_reg ;
				sprintf(hex_src_reg, "%X", p1.inst_list[i].src_reg); 
				sprintf(hex_dst_reg, "%X", p1.inst_list[i].dst_reg); 
				cout<<i<<"th instruction"<<endl;
				
				if(BPF_CLASS(p1.inst_list[i].code) == BPF_LD || BPF_CLASS(p1.inst_list[i].code) == BPF_LDX
				|| BPF_CLASS(p1.inst_list[i].code) == BPF_ST || BPF_CLASS(p1.inst_list[i].code) == BPF_STX){
					sprintf(hex_code, "%X", BPF_OP(p1.inst_list[i].code));
					//sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
					sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));
					
					int imm = p1.inst_list[i].imm;
					int off = p1.inst_list[i].off;
					int ins_class = BPF_CLASS(p1.inst_list[i].code);
					int code = BPF_OP(p1.inst_list[i].code);
					int size = BPF_SIZE(p1.inst_list[i].code);					

					//cout<<" Class :"<<BPF_CLASS(p1.inst_list[i].code)<<" Code :"<<hex_code<<" Size :"<<hex_size<<" Src reg : "<<hex_src_reg<<" Dst Reg : "<<hex_dst_reg<<" Imm :"<<p1.inst_list[i].imm<<" Off :"<<p1.inst_list[i].off<<endl;

					cout<<"Class :"<<ins_class<<" Code :"<<hex_code<<" Size :"<<hex_size<<" Src reg : "<<hex_src_reg<<" Dst Reg : "<<hex_dst_reg<<" Imm :"<<p1.inst_list[i].imm<<" Off :"<<p1.inst_list[i].off<<endl;
					
					parse_linebyline(hex_src_reg, hex_dst_reg, code ,ins_class, imm, off,size,it, itx);
					//cout<<"parse_linebyline is executing"<<endl;
				}
				else
				{
					sprintf(hex_mode, "%X", BPF_MODE(p1.inst_list[i].code));
					sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
					sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));
					int src_reg = p1.inst_list[i].src_reg;
					int dst_reg = p1.inst_list[i].dst_reg;
					int imm = p1.inst_list[i].imm;
					int off = p1.inst_list[i].off;
					int ins_class = BPF_CLASS(p1.inst_list[i].code);
					int mode = BPF_MODE(p1.inst_list[i].code);
					int size = BPF_SIZE(p1.inst_list[i].code);


					cout<<"Class :"<<ins_class<<" Mode :"<<hex_mode<<" Size :"<<hex_size<<" Src reg : "<<hex_src_reg<<" Dst Reg : "<<hex_dst_reg<<" Imm :"<<p1.inst_list[i].imm<<" Off :"<<p1.inst_list[i].off<<endl;
					parse_linebyline(hex_src_reg, hex_dst_reg, mode ,ins_class, imm, off, size, it ,itx);
				// cout<<"parse_linebyline is executing"<<endl;
				cout<<endl;
				}
			
				
			}
            print_reg_state(it);
			print_protocol();
			vector <int> new_protocol_check(4,0); 
			protocol_check = new_protocol_check;

		}

};

class Extract_helper_functions{
	private:
		set<int> parse_helper_ind(parse_inst insts){
			set<int> indexes;

			for(int i=0 ; i< insts.get_inst_cout() ; i++){
				if(BPF_OP(insts.inst_list[i].code) == BPF_CALL && BPF_SRC(insts.inst_list[i].code) == BPF_K){
					indexes.insert(insts.inst_list[i].imm);
					// cout << "\n BPF_CALL: " << BPF_CALL;
				}
			}
			return indexes;
		}
	public:

		map<int, string> helper_id_name;
		
		Extract_helper_functions() {

			//Helper function database
			helper_id_name = {{0,"unspec"},{1,"map_lookup_elem"},{2,"map_update_elem"},{3,"map_delete_elem"},{4,"probe_read"},{5,"ktime_get_ns"},{6,"trace_printk"},{7,"get_prandom_u32"},{8,"get_smp_processor_id"},{9,"skb_store_bytes"},{10,"l3_csum_replace"},
					{11,"l4_csum_replace"},{12,"tail_call"},{13,"clone_redirect"},{14,"get_current_pid_tgid"},{15,"get_current_uid_gid"},{16,"get_current_comm"},{17,"get_cgroup_classid"},{18,"skb_vlan_push"},{19,"skb_vlan_pop"},{20,"skb_get_tunnel_key"},
					{21,"skb_set_tunnel_key"},{22,"perf_event_read"},{23,"redirect"},{24,"get_route_realm"},{25,"perf_event_output"},{26,"skb_load_bytes"},{27,"get_stackid"},{28,"csum_diff"},{29,"skb_get_tunnel_opt"},{30,"skb_set_tunnel_opt"},{31,"skb_change_proto"},
					{32,"skb_change_type"},{33,"skb_under_cgroup"},{34,"get_hash_recalc"},{35,"get_current_task"},{36,"probe_write_user"},{37,"current_task_under_cgroup"},{38,"skb_change_tail"},{39,"skb_pull_data"},{40,"csum_update"},{41,"set_hash_invalid"},{42,"get_numa_node_id"},
					{43,"skb_change_head"},{44,"xdp_adjust_head"},{45,"probe_read_str"},{46,"get_socket_cookie"},{47,"get_socket_uid"},{48,"set_hash"},{49,"setsockopt"},{50,"skb_adjust_room"},{51,"redirect_map"},{52,"sk_redirect_map"},{53,"sock_map_update"},{54,"xdp_adjust_meta"},
					{55,"perf_event_read_value"},{56,"perf_prog_read_value"},{57,"getsockopt"},{58,"override_return"},{59,"sock_ops_cb_flags_set"},{60,"msg_redirect_map"},{61,"msg_apply_bytes"},{62,"msg_cork_bytes"},{63,"msg_pull_data"},{64,"bind"},{65,"xdp_adjust_tail"},
					{66,"skb_get_xfrm_state"},{67,"get_stack"},{68,"skb_load_bytes_relative"},{69,"fib_lookup"},{70,"sock_hash_update"},{71,"msg_redirect_hash"},{72,"sk_redirect_hash"},{73,"lwt_push_encap"},{74,"lwt_seg6_store_bytes"},{75,"lwt_seg6_adjust_srh"},{76,"lwt_seg6_action"},
					{77,"rc_repeat"},{78,"rc_keydown"},{79,"skb_cgroup_id"},{80,"get_current_cgroup_id"},{81,"get_local_storage"},{82,"sk_select_reuseport"},{83,"skb_ancestor_cgroup_id"},{84,"sk_lookup_tcp"},{85,"sk_lookup_udp"},{86,"sk_release"},{87,"map_push_elem"},{88,"map_pop_elem"},
					{89,"map_peek_elem"},{90,"msg_push_data"},{91,"msg_pop_data"},{92,"rc_pointer_rel"},{93,"spin_lock"},{94,"spin_unlock"},{95,"sk_fullsock"},{96,"tcp_sock"},{97,"skb_ecn_set_ce"},{98,"get_listener_sock"},{99,"skc_lookup_tcp"},{100,"tcp_check_syncookie"},
					{101,"sysctl_get_name"},{102,"sysctl_get_current_value"},{103,"sysctl_get_new_value"},{104,"sysctl_set_new_value"},{105,"strtol"},{106,"strtoul"},{107,"sk_storage_get"},{108,"sk_storage_delete"},{109,"send_signal"},{110,"tcp_gen_syncookie"},{111,"skb_output"},
					{112,"probe_read_user"},{113,"probe_read_kernel"},{114,"probe_read_user_str"},{115,"probe_read_kernel_str"},{116,"tcp_send_ack"},{117,"send_signal_thread"},{118,"jiffies64"},{119,"read_branch_records"},{120,"get_ns_current_pid_tgid"},{121,"xdp_output"},
					{122,"get_netns_cookie"},{123,"get_current_ancestor_cgroup_id"},{124,"sk_assign"},{125,"ktime_get_boot_ns"},{126,"seq_printf"},{127,"seq_write"},{128,"sk_cgroup_id"},{129,"sk_ancestor_cgroup_id"},{130,"ringbuf_output"},{131,"ringbuf_reserve"},{132,"ringbuf_submit"},
					{133,"ringbuf_discard"},{134,"ringbuf_query"},{135,"csum_level"},{136,"skc_to_tcp6_sock"},{137,"skc_to_tcp_sock"},{138,"skc_to_tcp_timewait_sock"},{139,"skc_to_tcp_request_sock"},{140,"skc_to_udp6_sock"},{141,"get_task_stack"},{142,"load_hdr_opt"},{143,"store_hdr_opt"},
					{144,"reserve_hdr_opt"},{145,"inode_storage_get"},{146,"inode_storage_delete"},{147,"d_path"},{148,"copy_from_user"},{149,"snprintf_btf"},{150,"seq_printf_btf"},{151,"skb_cgroup_classid"},{152,"redirect_neigh"},{153,"per_cpu_ptr"},{154,"this_cpu_ptr"},{155,"redirect_peer"},
					{156,"task_storage_get"},{157,"task_storage_delete"},{158,"get_current_task_btf"},{159,"bprm_opts_set"},{160,"ktime_get_coarse_ns"},{161,"ima_inode_hash"},{162,"sock_from_file"},{163,"check_mtu"},{164,"for_each_map_elem"},{165,"snprintf"},{166,"sys_bpf"},{167,"btf_find_by_name_kind"},
					{168,"sys_close"},{169,"timer_init"},{170,"timer_set_callback"},{171,"timer_start"},{172,"timer_cancel"},{173,"get_func_ip"},{174,"get_attach_cookie"},{175,"task_pt_regs"},{176,"get_branch_snapshot"},{177,"trace_vprintk"},{178,"skc_to_unix_sock"},{179,"kallsyms_lookup_name"},{180,"find_vma"},
					{181,"loop"},{182,"strncmp"},{183,"get_func_arg"},{184,"get_func_ret"},{185,"get_func_arg_cnt"},{186,"get_retval"},{187,"set_retval"},{188,"xdp_get_buff_len"},{189,"xdp_load_bytes"},{190,"xdp_store_bytes"},{191,"copy_from_user_task"},{192,"skb_set_tstamp"},{193,"ima_file_hash"},
					{194,"kptr_xchg"},{195,"map_lookup_percpu_elem"},{196,"skc_to_mptcp_sock"},{197,"dynptr_from_mem"},{198,"ringbuf_reserve_dynptr"},{199,"ringbuf_submit_dynptr"},{200,"ringbuf_discard_dynptr"},{201,"dynptr_read"},{202,"dynptr_write"},{203,"dynptr_data"},{204,"tcp_raw_gen_syncookie_ipv4"},
					{205,"tcp_raw_gen_syncookie_ipv6"},{206,"tcp_raw_check_syncookie_ipv4"},{207,"tcp_raw_check_syncookie_ipv6"},{208,"ktime_get_tai_ns"},{209,"user_ringbuf_drain"},{210,"cgrp_storage_get"},{211,"cgrp_storage_delete"},};

			// return helper_id_name[id];
		}

		vector<string> get_helper_list(parse_inst insts){


			set<int> helper_index = parse_helper_ind(insts);
			vector<string> helper_name_list;

			for (auto helper = helper_index.begin(); helper != helper_index.end(); ++helper){
				cout << ' ' << *helper;
				helper_name_list.push_back(helper_id_name[*helper]);	
			}
			return helper_name_list;
		}
};

int main(int argc, char *argv[]) {

	/*
	###################### Commands to compile: ######################
	$ g++ eBPF_parser.cpp -o parser -lbpf -lelf -lz -I/home/netx9/libbpf/include/uapi -L/usr/local/lib
	$ ./parser /home/netx9/Documents/eBPF_infra/main_folder/test_files/object_files/ether_ip_ipv6_tcp_udp.o xdp_parser_func
	*/

	// const char* filename = "/home/netx9/Documents/eBPF_infra/main_folder/test_files/xdp_pass_kern.o";
	// const char* filename = "/home/netx9/Desktop/animesh/ether_parse_new.o";
	// const char* filename = "/home/netx9/Desktop/animesh/ether_ip.o";
	// const char* filename = "/home/netx9/Documents/eBPF_infra/main_folder/test_files/xdp_pktcntr_opt.o";
	// const char* filename = "/home/netx9/Documents/eBPF_infra/main_folder/test_files/mptm.o";
	// const char* prog_name = "xdp_prog_simple";
	// const char* prog_name = "pktcntr";
	// const char* prog_name = "mptm_decap";
	const char* filename = argv[1];
	const char* prog_name = argv[2];

	if(argc > 2){
		cout << "\n File Name -> " << filename;
		cout << "\n eBPF program Name -> " << prog_name;
	}
	else{
		cout << "Please add <object_file.o> followed by the <program_name> as CLI arguments."<<endl;
		return(0);
	}

	// const char* filename = "/home/shiv/eBPF_infra/main_folder/test_files/xdp_pktcntr_opt.o";
	struct xdp_pass_kern* skel;
	struct bpf_object *obj;
	struct bpf_prog_skeleton* prog_skel;
	struct bpf_program *bpf_prog;
	const struct bpf_insn *orig_insn;

	state_array[0].tag = integer;
    state_array[0].value = garbage_value;
    state_array[10].tag = ptr_to_frame;
    state_array[10].value = garbage_value;
    state_array[1].tag = ptr_to_ctx;

	vector<edge> edge_list;

	parse_inst p1(filename, prog_name);

	enum {A,B,C,D,E,F,G,H,I,J,K};

	cout << p1.inst_count;

	for(int i=0 ; i<p1.inst_count ; i++){
		if(BPF_CLASS(p1.inst_list[i].code) == BPF_JMP || BPF_CLASS(p1.inst_list[i].code) == BPF_JMP32){
						
			edge ed;
			ed.src = i;
			ed.dst = i + p1.inst_list[i].off + 1;
			edge_list.push_back(ed);

			if(BPF_OP(p1.inst_list[i].code) == BPF_JGT || BPF_OP(p1.inst_list[i].code) == BPF_JGE 
			|| BPF_OP(p1.inst_list[i].code) == BPF_JSET || BPF_OP(p1.inst_list[i].code) == BPF_JNE
			|| BPF_OP(p1.inst_list[i].code) == BPF_JLT || BPF_OP(p1.inst_list[i].code) == BPF_JLE 
			|| BPF_OP(p1.inst_list[i].code) == BPF_JSLT || BPF_OP(p1.inst_list[i].code) == BPF_JSLE
			|| BPF_OP(p1.inst_list[i].code) == BPF_JEQ){
				/*NEED TO HANDLE THESE SCENARIOS*/
				/* FOR x86 JSGT is JGT*/
				/* FOR x86 JSGE is JGE*/
				edge ed;
				ed.src = i;
				ed.dst = i + 1;
				edge_list.push_back(ed);

				
			}

			if(BPF_OP(p1.inst_list[i+1].code) == BPF_EXIT){
				// cout <<  "$$$$ \n" << i;
				break;
			}
		}		
		else{
			
			edge ed;
			ed.src = i;
			ed.dst = i + 1;
			edge_list.push_back(ed);

			if(BPF_OP(p1.inst_list[ed.dst].code) == BPF_EXIT){
				cout <<  "  ####.." << ed.dst << " :: " << BPF_OP(p1.inst_list[ed.dst].code) << " :: " << BPF_EXIT;
				
				break;
			}
		}
		
	}
	cout << "\n edge_list: " << edge_list.size() ;
	cout << "\n inst_count: " << p1.inst_count ;

	CFGraph cfg(p1.inst_count);
	// Add edges:
	for(int i = 0 ; i < edge_list.size() ; i++){
		cfg.addEdge(edge_list.at(i).src, edge_list.at(i).dst);
		// cout << "\n" << edge_list.at(i).src << " >> " << edge_list.at(i).dst;
	}
	
	int s = 0, d = p1.inst_count-1;
	vector<vector<int>> allPaths;
    cout << "\nAll paths from " << s << " to " << d;	
	allPaths = cfg.get_all_paths(s, d);

	cout << "Size: " << allPaths.size();

	for(int i=0 ; i<allPaths.size() ; i++){
		cout << "\n" << i << ": ";
		for(int j=0 ; j<allPaths.at(i).size() ; j++){
			cout << " " << allPaths.at(i).at(j);
		}
		cout << "\n";
	}

	// flow_prop fp;

	// fp.get_information(p1);

	// //This for loop will print the state_array
    // for(int i = 0 ; i<11 ; i++){
    //     cout<<"Register "<<i<<" tag :"<<state_array[i].tag<<" Value : "<<state_array[i].value<<endl;
    // }

	cout << "\n";  

	Extract_helper_functions helpers;
	vector<string> helper_names = helpers.get_helper_list(p1);

	cout << "\n"; 

	//Executing "register tagging"
	flow_prop fp;
    for(int it = 0 ; it<allPaths.size(); it++){
		//re_initialize_state_array();
		fp.get_information(p1,it);
	}

	cout << "\n";  

	cout << "\nList of helper functions: ";
	for(int i=0 ; i < helper_names.size() ; i++){
		cout << "\nHelper : " <<"bpf_"<< helper_names.at(i);
	}

	cout << "\n"; 
    return 0;
}